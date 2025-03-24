package client

import (
	"context"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"strconv"
	"time"
)

// DNSClient is the client to exchange DNS messages with a server.
// It is the main type of the client package.
type DNSClient struct {
	Inner DNSClientDecorator
}

// DNSClientDecorator is the interface for DNS clients to implement a decorator pattern
type DNSClientDecorator interface {
	Enqueue(correlationId uint64, q Question, ip Address, sendOpts SendOpts)
	ResponseChan() <-chan Response
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// SendOpts is the type that tells the client how to do exchange of DNS messages on a per-request level.
type SendOpts struct {
	UseTCP       bool
	SetDO        bool
	DisableEDNS0 bool
	Log          zerolog.Logger
}

// DefaultSendOpts are the SendOpts used if nothing is overwritten by providing Option or by the client itself (e.g. when a TCP fallback is dones)
var DefaultSendOpts = SendOpts{
	UseTCP:       false,
	SetDO:        false,
	DisableEDNS0: false,
}

type Address interface {
	Is6() bool
	String() string
}

// Response is the response to a DNS message exchange
type Response struct {
	// The correlationId provided in the Enqueue() call.
	// Use to map requests with responses.
	CorrelationId uint64

	// ConnId uniquely specifies the connection that was used to send the request
	ConnId uint64

	// The response message
	Message *dns.Msg

	// The address from which the response was received
	ResponseAddr string

	// Error that occurred during the exchange
	Error error

	// TCP is true if the request was sent with TCP
	// False if the request was sent with UDP
	TCP bool

	// The address to which the query was sent
	NameServerIP Address

	// RTT is the time from sending the query until receiving a response (or timeout)
	RTT time.Duration
}

// An Option is modifies the exchange of DNS messages
type Option func(*SendOpts) // For implementation details: https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html

// Enqueue enqueues a request for processing.
// Responses can be received using Dequeue.
// If the buffer of the client is full, (i.e. more requests are added than can be processed)
// enqueue blocks until a place in the queue is freed, thus applying backpressure on the system.
// No order must be assumed between messages sent and received.
// For example slow responses by nameservers or rate limiting can lead to a reordering of the responses.
func (c DNSClient) Enqueue(correlationId uint64, q Question, ip Address, opts ...Option) {
	sendOpts := DefaultSendOpts

	// https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
	for _, opt := range opts {
		opt(&sendOpts)
	}

	sendOpts.Log = sendOpts.Log.With().
		Str("correlationId", strconv.FormatUint(correlationId, 10)).
		Interface("ns", ip).
		Interface("question", q).
		Logger()

	c.Inner.Enqueue(correlationId, q, ip, sendOpts)
}

// Dequeue receives a response of a request sent via Enqueue.
// If no response is available it blocks.
// No relation must be assumed between the order or cardinality of messages sent and received.
// For example slow responses by nameservers or rate limiting will lead to a "reordering" of the responses
func (c DNSClient) Dequeue(ctx context.Context) Response {
	select {
	case <-ctx.Done():
		return Response{Error: ErrCancelled}
	case res := <-c.Inner.ResponseChan():
		return res
	}
}

// If applies the option only if the provided flag is true.
func If(apply bool, opt Option) Option {
	if apply {
		return opt
	}

	return func(so *SendOpts) {
		// no op
	}
}

// UseTCP is the option to use TCP for the query
func UseTCP() Option {
	return func(opts *SendOpts) {
		opts.UseTCP = true
	}
}

// SetDO is the option to set or unset the DO bit in the DNS query.
func SetDO(value bool) Option {
	return func(opts *SendOpts) {
		opts.SetDO = value
	}
}

// DisableEDNSO disables the use of dns extensions for this request.
// SetDO has no effect anymore.
func DisableEDNSO() Option {
	return func(opts *SendOpts) {
		opts.DisableEDNS0 = true
	}
}

// LogTo is the option to use a specific logger for the request
func LogTo(log zerolog.Logger) Option {
	return func(opts *SendOpts) {
		opts.Log = log
	}
}
