package udp

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/godruoyi/go-snowflake"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

var _ client.DNSClientDecorator = new(Client)

// ConnFactory manages connections (e.g. a connection pool)
type ConnFactory interface {
	GetOrCreate(onReceive ReceiveCallback) (*PooledConn, error)
}

// Client is a DNS client that exchanges UDP messages
type Client struct {
	// DestinationPort is the port to which messages are sent (usually 53)
	DestinationPort uint16

	// ReceiveTimeout is the time after which a message exchange times out
	ReceiveTimeout time.Duration

	// WriteTimeout is the timeout after which write operations fail.
	WriteTimeout time.Duration

	// udpSize is the size used for UDP packets if EDNS extensions are enabled.
	// If EDNS is disabled for the exchange, the DNS default of 512 is used.
	udpSize uint16

	// poolV4 is the underlying pool that manages the UDP sockets for IPv4 connections
	poolV4 ConnFactory

	// poolV6 is the underlying pool that manages the UDP sockets for IPv6 connections
	poolV6 ConnFactory

	// responseChan is the channel to which responses are written.
	// Exposed via function ResponseChan()
	responseChan chan client.Response

	// inflight contains an entry for each open message.
	// It is used to map the responses to the requests by mapping
	// (connection, msgID) => correlationId
	inflight sync.Map
}

// inflightKey is a key for Client.inflight
type inflightKey struct {
	connId uint64
	msgId  uint16
}

// inflightVal is a value of Client.inflight
type inflightVal struct {
	correlationId uint64
	question      client.Question
	ip            client.Address
	sendTime      time.Time
	stopTimeout   func()
}

func NewClient(poolV4 ConnFactory, poolV6 ConnFactory, udpTimeout time.Duration, udpSize uint16) *Client {
	return &Client{
		poolV4:          poolV4,
		poolV6:          poolV6,
		DestinationPort: internal.DefaultDNSPort,
		ReceiveTimeout:  udpTimeout,
		WriteTimeout:    time.Second,
		udpSize:         udpSize,
		responseChan:    make(chan client.Response, internal.DefaultResponseChannelBuffer),
		inflight:        sync.Map{},
	}
}

func (c *Client) ResponseChan() <-chan client.Response {
	return c.responseChan
}

func (c *Client) Enqueue(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts) {
	var conn *PooledConn
	var err error

	if ip.Is6() {
		conn, err = c.poolV6.GetOrCreate(c.onReceive)
	} else {
		conn, err = c.poolV4.GetOrCreate(c.onReceive)
	}

	if err != nil { // Error when establishing the connection, e.g. Dial Timeout
		c.responseChan <- internal.ErrorResponse(correlationId, 0, ip, "", 0, false, err)
		return
	}

	// From RFC7828
	// DNS clients MUST NOT include the edns-tcp-keepalive option in queries
	// sent using UDP transport.
	msg := internal.CreateWireMessage(q, sendOpts.DisableEDNS0, c.udpSize, sendOpts.SetDO)
	msg.Id = conn.GetFreeMessageID()

	key := inflightKey{
		connId: conn.Id,
		msgId:  msg.Id,
	}

	atomicTimer := atomic.Value{}
	c.inflight.Store(key, inflightVal{
		correlationId: correlationId,
		question:      q,
		ip:            ip,
		sendTime:      time.Now(),
		stopTimeout: func() {
			timer := atomicTimer.Load()
			if timer == nil {
				return
			}
			if t, ok := timer.(*time.Timer); ok {
				t.Stop()
				return
			}

			// Should never happen
			panic("unknown type stored in atomic timer")
		},
	})

	if err = conn.WriteMessageTo(msg, ip, c.DestinationPort, c.WriteTimeout); err != nil {
		c.inflight.Delete(key)
		c.responseChan <- internal.ErrorResponse(correlationId, snowflake.ID(), ip, "", 0, false, err)

		return
	}

	// The timeout - if after x seconds the entry is still in the map, return a timeout
	timeout := time.AfterFunc(c.ReceiveTimeout, func() {
		if entry, loaded := c.inflight.LoadAndDelete(key); loaded {
			value, ok := entry.(inflightVal)
			if !ok { // If it happens, we have a bug
				panic("unknown type of entry in inflight map")
			}

			c.responseChan <- internal.ErrorResponse(correlationId, snowflake.ID(), ip, "", time.Since(value.sendTime), false, client.ErrReceiveTimeout)
		}

		// ReleaseMessageID will wait for a bit until releasing the message id for reuse.
		// This should prevent a late message to be correlated with a new request with the same id
		conn.ReleaseMessageID(msg.Id)
	})
	atomicTimer.Store(timeout)
}

func (c *Client) onReceive(connId uint64, msg *dns.Msg, addr string, err error) {
	entry, loaded := c.inflight.LoadAndDelete(inflightKey{
		msgId:  msg.Id,
		connId: connId,
	})

	// Unsolicited or late message - we still pass it to the caller, so it can decide what to do with it (probably log and forget)
	if !loaded {
		client.Metrics.UncorrelatedMessages.Inc()
		c.responseChan <- internal.UnsolicitedResponse(connId, addr, msg, false)

		return
	}

	value, ok := entry.(inflightVal)
	if !ok {
		panic("unknown type of entry in inflight map")
	}

	value.stopTimeout()
	rtt := time.Since(value.sendTime)
	client.Metrics.QueriesRTT.Observe(rtt.Seconds())

	if err != nil {
		c.responseChan <- internal.ErrorResponse(value.correlationId, connId, value.ip, addr, rtt, false, err)
		return
	}

	c.responseChan <- internal.MessageResponse(value.correlationId, connId, value.ip, addr, msg, rtt, false)
}
