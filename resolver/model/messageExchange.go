package model

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/miekg/dns"
	"net/netip"
	"time"
)

// MessageExchange represents the exchange of a model.Message with a model.NameServer
type MessageExchange struct {
	// OriginalQuestion contains the question that was asked.
	// in contrast to Message.Question, which returns the question as returned by the name server.
	// Unless the nameserver misbehaves, they should match.
	OriginalQuestion Question

	ResponseAddr string
	NameServerIP netip.Addr

	Metadata Metadata

	Message *dns.Msg

	// Error contains errors like timeouts or connection refusal that occurred during the exchange.
	// If no error occurred, it is nil
	Error *SendError
}

type Metadata struct {
	FromCache     bool
	RetryIdx      uint
	ConnId        uint64
	TCP           bool
	IsFinal       bool
	CorrelationId uint64
	ParentId      uint64
	EnqueueTime   time.Time
	DequeueTime   time.Time
	RTT           time.Duration
}

func (msg *MessageExchange) IsSuccess() bool {
	return msg.Error == nil && !msg.Message.Truncated && msg.Message.Rcode == client.RcodeSuccess
}

// SendError represents an error when communicating with a DNS name server like a timeout or a connection refusal.
type SendError struct {
	Message string
	Code    ErrorCode
}

type ErrorCode string

const (
	ErrorCodeNone       = ""
	ErrorCodeDoNotScan  = "DO_NOT_SCAN"
	ErrorCodeDstunreach = "DST_UNREACH"
	ErrorCodeSendError  = "SEND_ERR"
)
