package tcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/godruoyi/go-snowflake"
	"github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var errWrittenTooManyBytes = fmt.Errorf("written more bytes than there are in the message")

// dialFunc is the function used for opening the actual TCP connection.
// You can replace it with a custom function for unit testing.
var dialFunc = net.DialTimeout

type ReceiveCallback func(*PooledConn, *dns.Msg, string, error)

// PooledConn is a connection that can be used by multiple processes.
// QueriesSent are send using WriteMessage and can be received in two ways.
// Either use the blocking ReadMessage or register a callback with StartReceiving
// Consider that queries should be pipelined and can be received out-of-order
//
// From RFC7766:
//
//	In order to achieve performance on par with UDP, DNS clients SHOULD
//	pipeline their queries.  When a DNS client sends multiple queries to
//	a server, it SHOULD NOT wait for an outstanding reply before sending
//	the next query.
type PooledConn struct {
	*internal.MessageIdGenerator

	// ID is the unique identifier of the connection.
	ID uint64

	// DestinationIP is the address of the name server to which the connection is established.
	DestinationIP client.Address

	// DestinationPort contains the port that is contacted
	DestinationPort uint16

	inner net.Conn

	// writeMu is used internally for synchronizing writes.
	// We use a semaphore instead of a mutex because it can time out.
	writeMu *semaphore.Weighted

	// init runs the initialization of the connection exactly once
	init sync.Once

	// initErr contains errors that occurred in the initialization routine
	initErr atomic.Value

	// onReceive is the callback invoked when a message is received
	onReceive ReceiveCallback

	// onClose is the callback invoked when the connection is closed
	// It is invoked exactly once.
	onClose func()

	// closeOnce ensures that onClose is invoked exactly once
	closeOnce sync.Once

	// inflightCount keeps track of the number of inflight queries
	inflightCount *semaphore.Weighted

	closeWithRST bool
}

// We need this to store the interface type "error" inside atomic.Value
type errWrap struct {
	err error
}

// newPooledConn creates initializes a new PooledConn
func newPooledConn(destinationAddress client.Address, destinationPort uint16) *PooledConn {
	return &PooledConn{
		MessageIdGenerator: internal.NewIdGen(),
		ID:                 snowflake.ID(),
		DestinationIP:      destinationAddress,
		DestinationPort:    destinationPort,
		writeMu:            semaphore.NewWeighted(1),
		inflightCount:      semaphore.NewWeighted(math.MaxInt64),
	}
}

// CloseNow closes the connection immediately.
// Equivalent to calling Close(context.Background(), 0)
func (conn *PooledConn) CloseNow() {
	conn.Close(context.Background(), 0)
}

// Close closes the connection after all inflight messages are received or after the specified grace period is over.
// Immediately after Close was called, calls to WriteMessage will return ErrGracePeriodBegun.
// If there are no inflight messages, Close closes immediately.
// The main use case for this method is to allow gracefully discarding a connection in accordance to rfc7828:
//
//	A DNS client that receives a response that includes the edns-tcp-
//	keepalive option with a TIMEOUT value of 0 SHOULD send no more
//	queries on that connection and initiate closing the connection as
//	soon as it has received all outstanding responses.
func (conn *PooledConn) Close(ctx context.Context, gracePeriod time.Duration) {
	conn.closeOnce.Do(func() {
		if conn.onClose != nil {
			conn.onClose()
		}

		// If inner is nil, there was a dial error -> we don't need to close anything
		if conn.inner == nil {
			return
		}

		// We give the server a chance to respond to open messages
		ctx, cancel := context.WithTimeout(ctx, gracePeriod)
		_ = conn.inflightCount.Acquire(ctx, math.MaxInt64)
		cancel()

		if conn.closeWithRST {
			// Linger=0 sends a RST instead of a CLOSE when the connection is closed, freeing the port immediately and avoiding many connections in state TIME_WAIT
			// It has drawbacks, as discussed in the links but according to rfc1035 it should be ok to use it.
			// RFC1035: Since the server would be unable to answer queries anyway, a unilateral close or reset may be used instead of a tcpGracefulClose close.
			// http://www.serverframework.com/asynchronousevents/2011/01/time-wait-and-its-design-implications-for-protocols-and-scalable-servers.html
			// https://stackoverflow.com/questions/3757289/when-is-tcp-option-so-linger-0-require
			if tcpConn, isTcp := conn.inner.(*net.TCPConn); isTcp {
				tcpConn.SetLinger(0)
			}
		}

		_ = conn.inner.Close()
	})
}

// DialOnce initializes the connection. It runs exactly once, even when called repeatedly or in parallel.
func (conn *PooledConn) DialOnce(timeout time.Duration) error {
	conn.init.Do(func() {
		c, err := dialFunc("tcp", internal.FormatWithPort(conn.DestinationIP, conn.DestinationPort), timeout)
		if err != nil {
			client.Metrics.TCPDialErrors.Inc()
			conn.initErr.Store(errWrap{err: err})
			return
		}

		// TODO - race condition analyzer says theres a race writing and reading value of inner
		conn.inner = c
	})

	if val := conn.initErr.Load(); val != nil {
		if wrapper, ok := val.(errWrap); ok {
			return wrapper.err
		}
	}
	return nil
}

func (conn *PooledConn) StartReceiving(callback ReceiveCallback) error {
	if conn.inner == nil {
		return client.ErrReceiveOnClosedConn
	}

	conn.onReceive = callback

	go conn.receiveWorker()
	return nil
}

// WriteMessage writes the message on the wire.
func (conn *PooledConn) WriteMessage(msg *dns.Msg, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	// This should never fail, unless CloseWithGracePeriod was called
	if acquired := conn.inflightCount.TryAcquire(1); !acquired {
		return client.ErrGracePeriodBegun
	}

	p, _ := msg.Pack()
	if len(p) > dns.MaxMsgSize {
		return client.ErrMessageTooLarge
	}
	if err := conn.inner.SetWriteDeadline(deadline); err != nil {
		conn.inflightCount.Release(1)
		return client.ErrWriteMessage.Wrap(err)
	}

	actualBytes := make([]byte, 2+len(p)) //nolint:mnd
	binary.BigEndian.PutUint16(actualBytes, uint16(len(p)))
	copy(actualBytes[2:], p)

	// Only allow one writer at a time.
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := conn.writeMu.Acquire(ctx, 1); err != nil {
		conn.inflightCount.Release(1)
		return client.ErrWriteMessage.Wrap(err)
	}
	defer conn.writeMu.Release(1)

	total := 0

	for total < len(actualBytes) {
		n, err := conn.inner.Write(actualBytes[total:])
		total += n
		if err != nil {
			conn.inflightCount.Release(1)
			return client.ErrWriteMessage.Wrap(err)
		}
	}

	// Should never happen
	if total != len(actualBytes) {
		return errWrittenTooManyBytes
	}

	client.Metrics.IncSentTCPQueries(conn.DestinationIP.Is6())

	return nil
}

func (conn *PooledConn) receiveWorker() {
	for {
		msg, err := conn.ReadMessage(time.Time{}) // No timeout - will run until connection is closed

		if err != nil {
			conn.onReceive(conn, msg, internal.FormatWithPort(conn.DestinationIP, conn.DestinationPort), err)
			break
		}

		client.Metrics.IncRecTCPQueries(conn.DestinationIP.Is6())
		go conn.onReceive(conn, msg, internal.FormatWithPort(conn.DestinationIP, conn.DestinationPort), err)
	}
}

// ReadMessage reads the next message from the connection.
func (conn *PooledConn) ReadMessage(deadline time.Time) (*dns.Msg, error) {
	const headerSize = 12
	var length uint16

	if err := conn.inner.SetReadDeadline(deadline); err != nil {
		return nil, client.ErrRead.Wrap(err)
	}

	if err := binary.Read(conn.inner, binary.BigEndian, &length); errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, client.ErrReceiveTimeout.Wrap(err)
	} else if err != nil {
		return nil, client.ErrRead.Wrap(err)
	}

	p := make([]byte, length)
	n, err := io.ReadFull(conn.inner, p)

	if err != nil {
		return nil, client.ErrRead.Wrap(err)
	}
	if n < headerSize {
		return nil, client.ErrCorruptedMessage
	}

	p = p[:n]

	m := new(dns.Msg)
	if err = m.Unpack(p); err != nil {
		err = client.ErrCorruptedMessage.Wrap(err) // Wrap in our custom error
	}
	if conn.ReleaseMessageID(m.Id) {
		conn.inflightCount.Release(1)
	}
	return m, err
}
