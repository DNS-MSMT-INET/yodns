package tcp

import (
	"errors"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/miekg/dns"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

var _ client.DNSClientDecorator = new(Client)

// ConnFactory manages connections (e.g. a connection pool)
type ConnFactory interface {
	GetOrCreate(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error)
	CreateEphemeral(remoteIP client.Address, remotePort uint16) (*PooledConn, error)
}

// Client is a DNS client that exchanges TCP messages
type Client struct {
	// DestinationPort is the port to which messages are sent (usually 53)
	DestinationPort uint16

	// ReceiveTimeout is the time after which a message exchange times out
	ReceiveTimeout time.Duration

	// WriteTimeout is the timeout after which write operations fail.
	WriteTimeout time.Duration

	// KeepAlive enables or disables usage of the EDNS0 extension for TCP Keepalive (RFC7828)
	// If the default value for time.Duration is used, the feature is disabled.
	// Otherwise, the specified period will be requested.
	KeepAlive time.Duration

	// pool is the underlying connection pool that manages the TCP connection lifecycle
	pool ConnFactory

	// responseChan is the channel to which responses are written.
	// Exposed via function ResponseChan()
	responseChan chan client.Response

	// inflight contains an entry for each open message.
	// Used to determine unsolicited messages.
	// (connId, messageId) -> inflightVal
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
	ip            client.Address
	q             client.Question
	sendOpts      client.SendOpts
	sendTime      time.Time
	stopTimeout   func()
}

func NewClient(pool ConnFactory, timeout time.Duration, keepAlive time.Duration) *Client {
	c := &Client{
		pool:            pool,
		KeepAlive:       keepAlive,
		WriteTimeout:    time.Second,
		ReceiveTimeout:  timeout,
		DestinationPort: internal.DefaultDNSPort,
		responseChan:    make(chan client.Response, internal.DefaultResponseChannelBuffer),
		inflight:        sync.Map{},
	}

	return c
}

func (c *Client) ResponseChan() <-chan client.Response {
	return c.responseChan
}

func (c *Client) Enqueue(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts) {
	conn, err := c.pool.GetOrCreate(ip, c.DestinationPort, c.onReceive)

	var cerr client.Error
	if errors.As(err, &cerr) && cerr.Code == client.ErrorCodePoolExhausted {
		go c.fallbackEphemeral(q, ip, sendOpts, correlationId)
		return
	}

	if err != nil {
		c.responseChan <- internal.ErrorResponse(correlationId, 0, ip, "", 0, true, err)
		return
	}

	// From rfc8906
	// 3.2.7. EDNS over TCP: Some EDNS-aware servers incorrectly limit the TCP response sizes to the advertised UDP response size.
	// => We must set it to 0. Not setting it is not an option, as it is encoded in the mandatory class field for the OPT RR
	// If that fails, we still have the fallback to no EDNS.
	msg := internal.CreateWireMessage(q, sendOpts.DisableEDNS0, 0, sendOpts.SetDO)
	if c.KeepAlive != 0 {
		internal.SetTCPKeepalive(msg, c.KeepAlive)
	}
	msg.Id = conn.GetFreeMessageID() // Never 0

	key := inflightKey{
		connId: conn.ID,
		msgId:  msg.Id,
	}

	atomicTimer := atomic.Value{}
	c.inflight.Store(key, inflightVal{
		correlationId: correlationId,
		ip:            ip,
		q:             q,
		sendOpts:      sendOpts,
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

	if err = conn.WriteMessage(msg, c.WriteTimeout); err != nil {
		if _, loaded := c.inflight.LoadAndDelete(key); !loaded {
			return // someone else responded, maybe the message got trough - super rare case, if it exists at all.
		}
		conn.CloseNow()
		nsIp := internal.FormatWithPort(conn.DestinationIP, conn.DestinationPort)
		c.responseChan <- internal.ErrorResponse(correlationId, conn.ID, ip, nsIp, 0, true, client.ErrWriteMessage.Wrap(err))

		return
	}

	// The timeout - if after x seconds the entry is still in the map, return a timeout
	timeout := time.AfterFunc(c.ReceiveTimeout, func() {
		if entry, loaded := c.inflight.LoadAndDelete(key); loaded {
			conn.CloseNow()
			value, ok := entry.(inflightVal)
			if !ok {
				panic("unknown type of entry in inflightVal")
			}

			// Why do we retry ephemeral?
			// There are servers, that keep a TCP connection open, but only respond to the first query.
			// What happens: We send 10 queries, we get 9 timeouts - we need to retry!
			// If we retry with a pooled connection, next time we will send 9 queries and get 8 timeouts.
			// So we need to retry with a one-time use connection.
			// A future optimisation might be to track these in the infrastructure cache and use ephemeral directly.
			// The disadvantage of our fallback here are
			// - that the callee might actually wait 2*ReceiveTimeout until it gets a response.
			// - that it puts more loads on servers that can pool connections but terminate them for any reason
			c.fallbackEphemeral(value.q, value.ip, value.sendOpts, value.correlationId)
		}
	})

	atomicTimer.Store(timeout)
}

func (c *Client) onReceive(conn *PooledConn, msg *dns.Msg, addr string, err error) {
	// On error, throw away the connection
	if err != nil {
		conn.CloseNow()
	}

	// Error case
	// Id is never zero unless it was not parsed
	if err != nil || msg == nil || msg.Id == 0 {
		// From RFC7766
		// DNS clients SHOULD retry unanswered queries if the connection closes
		// before receiving all outstanding responses. No specific retry
		// algorithm is specified in this document.
		resubmitEphemeral(conn, c)
		return
	}

	entry, loaded := c.inflight.LoadAndDelete(inflightKey{
		msgId:  msg.Id,
		connId: conn.ID,
	})
	if !loaded {
		client.Metrics.UncorrelatedMessages.Inc()
		c.responseChan <- internal.UnsolicitedResponse(conn.ID, addr, msg, true)

		return
	}

	value, ok := entry.(inflightVal)
	if !ok {
		panic("unknown type of entry in inflightVal")
	}
	value.stopTimeout()

	rtt := time.Since(value.sendTime)
	client.Metrics.QueriesRTT.Observe(rtt.Seconds())
	c.responseChan <- internal.MessageResponse(value.correlationId, conn.ID, value.ip, addr, msg, rtt, true)
}

func resubmitEphemeral(conn *PooledConn, c *Client) {
	ids := conn.InflightIDs()
	for _, id := range ids {
		entry, loaded := c.inflight.LoadAndDelete(inflightKey{
			msgId:  id,
			connId: conn.ID,
		})
		if !loaded {
			continue
		}

		value, ok := entry.(inflightVal)
		if !ok {
			panic("unknown type of entry in inflightVal")
		}

		value.stopTimeout()

		go func() {
			// Add some jitter, so if many queries are inflight, we don't open all the TCP conns simultaneously
			//nolint:gosec // Weak random number generator
			time.Sleep(time.Millisecond * time.Duration(rand.Int31n(internal.DefaultJitterInMs)))
			c.fallbackEphemeral(value.q, value.ip, value.sendOpts, value.correlationId)
		}()
	}
}

func (c *Client) fallbackEphemeral(q client.Question, ip client.Address, sendOpts client.SendOpts, correlationId uint64) {
	conn, err := c.pool.CreateEphemeral(ip, c.DestinationPort)
	if err != nil {
		c.responseChan <- internal.ErrorResponse(correlationId, 0, ip, "", 0, true, err)
		return
	}

	defer conn.CloseNow()

	// Messages sent via ephemeral connections do not set the EDNS0 tcp keepalive option
	msg := internal.CreateWireMessage(q, sendOpts.DisableEDNS0, 0, sendOpts.SetDO)

	if err = conn.WriteMessage(msg, c.WriteTimeout); err != nil {
		c.responseChan <- internal.ErrorResponse(correlationId, conn.ID, ip, "", 0, true, err)
		return
	}
	sendTime := time.Now()

	respMsg, err := conn.ReadMessage(sendTime.Add(c.ReceiveTimeout))
	if err != nil {
		c.responseChan <- internal.ErrorResponse(correlationId, conn.ID, ip, "", time.Since(sendTime), true, err)
		return
	}

	nsIP := internal.FormatWithPort(conn.DestinationIP, conn.DestinationPort)
	c.responseChan <- internal.MessageResponse(correlationId, conn.ID, ip, nsIP, respMsg, time.Since(sendTime), true)
}
