package udp

import (
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/godruoyi/go-snowflake"
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"time"
)

var errWrittenTooManyBytes = fmt.Errorf("not the whole message was written")

// PooledConn is a wrapper around connection stored in the UDP connection pool.
type PooledConn struct {
	*internal.MessageIdGenerator

	Id     uint64
	faulty int32

	IsIPV6 bool

	inner   net.PacketConn
	udpSize uint16

	onReceive ReceiveCallback
}

type ReceiveCallback func(uint64, *dns.Msg, string, error)

func newPooledUDPConn(udpSize uint16, isIPV6 bool, inner net.PacketConn) *PooledConn {
	if udpSize < dns.MinMsgSize {
		panic(fmt.Sprintf("minimum message size is %v", dns.MinMsgSize))
	}

	conn := &PooledConn{
		inner:              inner,
		Id:                 snowflake.ID(),
		MessageIdGenerator: internal.NewIdGen(),
		udpSize:            udpSize,
		IsIPV6:             isIPV6,
	}

	return conn
}

func (conn *PooledConn) Close() {
	if conn.inner != nil {
		conn.inner.Close()
	}
}

func (conn *PooledConn) IsFaulty() bool {
	return atomic.LoadInt32(&conn.faulty) == 1
}

func (conn *PooledConn) ID() uint64 {
	return conn.Id
}

func (conn *PooledConn) StartReceiving(onReceive ReceiveCallback) {
	conn.onReceive = onReceive
	go conn.receiveWorker()
}

func (conn *PooledConn) WriteMessageTo(msg *dns.Msg, remoteIP client.Address, remotePort uint16, timeout time.Duration) error {
	remoteAddr, err := net.ResolveUDPAddr("udp", internal.FormatWithPort(remoteIP, remotePort))
	if err != nil {
		return client.ErrInvalidAddress.Wrap(err)
	}

	p, _ := msg.Pack()
	if len(p) > dns.MaxMsgSize {
		return client.ErrMessageTooLarge
	}

	deadline := time.Now().Add(timeout)
	if err = conn.inner.SetWriteDeadline(deadline); err != nil {
		atomic.StoreInt32(&conn.faulty, 1) // Write timeout
		conn.Close()

		return client.ErrWriteMessage.Wrap(err)
	}

	n, err := conn.inner.WriteTo(p, remoteAddr)

	if err != nil {
		return client.ErrWriteMessage.Wrap(err)
	}

	// If this happens, that means we need to call inner.WriteTo in a loop until everything is written and we need to lock it before we do that
	if n != len(p) {
		return client.ErrWriteMessage.Wrap(errWrittenTooManyBytes)
	}

	client.Metrics.IncSentUDPQueries(remoteIP.Is6())

	return nil
}

func (conn *PooledConn) receiveWorker() {
	for {
		bytes, addr, err := conn.readNextPacket()

		// Stop worker. Setting conn.Faulty will trigger removal from the pool.
		if err != nil {
			atomic.StoreInt32(&conn.faulty, 1)
			conn.Close()

			return
		}

		msg := new(dns.Msg)
		if err = msg.Unpack(bytes); err != nil {
			err = client.ErrCorruptedMessage.Wrap(err)
		}

		conn.ReleaseMessageID(msg.Id)

		client.Metrics.IncRecUDPQueries(conn.IsIPV6)
		go conn.onReceive(conn.Id, msg, addr.String(), err)
	}
}

func (conn *PooledConn) readNextPacket() ([]byte, net.Addr, error) {
	bytes := make([]byte, conn.udpSize)
	n, addr, err := conn.inner.ReadFrom(bytes)

	if n <= 0 || err != nil {
		return nil, nil, client.ErrRead.Wrap(err)
	}

	return bytes[:n], addr, nil
}
