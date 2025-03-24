package resolver

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/enriquebris/goconcurrentqueue"
	"github.com/godruoyi/go-snowflake"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type DNSClient interface {
	Enqueue(correlationId uuid.UUID, q model.Question, ip client.Address, opts ...client.Option)
	ResponseChan() <-chan Response
}

type QueryCache interface {
	Set(msg model.MessageExchange)
	Get(nsIP netip.Addr, q model.Question) (model.MessageExchange, bool)
}

type InfraCache interface {
	Track(msg model.MessageExchange)
	GetBackoff(nsIP netip.Addr) time.Duration
	IsResponsive(nsIP netip.Addr) (udpResponsive bool, tcpResponsive bool, reason string)
}

type serverStatus struct {
	udpResponsive bool
	tcpResponsive bool
	reason        string
}

// RequestWorker is a worker that does the following things
//   - Enqueue requests to the DNS client
//   - dequeue responses from the DNS client and correlating them with the requests
//   - Enqueue again, if the query needs to be retried
//   - do cache lookups to check if the responses are already there
type RequestWorker struct {
	correlationMap *sync.Map // in case of performance issues, maybe try https://github.com/alphadose/haxmap
	client         client.DNSClient
	cache          QueryCache
	infraCache     InfraCache
	maxRetries     uint
	log            zerolog.Logger
	disableTCP     bool
	disableUDP     bool
}

// NewWorker initializes a new RequestWorker posting to and reading from the configured dns client.
func NewWorker(client client.DNSClient, cache QueryCache, infraCache InfraCache, maxRetries uint) *RequestWorker {
	return &RequestWorker{
		correlationMap: &sync.Map{},
		client:         client,
		cache:          cache,
		infraCache:     infraCache,
		maxRetries:     maxRetries,
	}
}

// Request is a request to the worker.
type Request struct {
	// parentCorrelationId is the correlationId of the message exchange that is the
	// logical parent of this exchange (i.e. the message that "caused" the next message).
	// It is optional, but useful to understand how the resolver is working.
	parentCorrelationId uint64

	// The question to ask the name server
	question model.Question

	// The Conn-address(es) of the name server to query
	nameServerIP netip.Addr

	// Name of the name server
	nameServerName model.DomainName

	// The queue to which the response will be posted.
	responseQueue goconcurrentqueue.Queue

	// If true, UDP will be used for the query. There will be no TCP fallback.
	disableTCPFallback bool

	// If true, the query will not be answered from the cache. The answer will still be put into the cache.
	skipCache bool

	// If true, the request will not be tracked in the infrastructure cache.
	disableInfraCache bool

	// Value of the DNSSEC OK bit
	do bool

	// Arbitrary additional data that is passed on to the response channel.
	// Use this to carry additional data over to the next round of analysis
	data any

	// If true, EDNS0 will be disabled for the query.
	disableEDNS0 bool

	// maxRetries controls how many times the request should be retried if it fails
	// If nil, the default will be used.
	maxRetries *uint

	log zerolog.Logger
}

// Response is the response to a Request
type Response struct {
	// msgExchange is the response message.
	msgExchange model.MessageExchange

	// Name of the name server
	nameServerName model.DomainName

	// carryOverArgs contains arbitrary carryOverArgs carried over from the request.
	carryOverArgs any
}

// correlationMapEntry is a small helper stored for every open request to correlate it with the response later.
type correlationMapEntry struct {
	// request contains the enqueued request
	request Request

	// retryCount is the index of the retry.
	// 0 for the initial request, 1 if the initial request failed and the request is enqueued again, and so on
	retryCount uint

	// enqueueTime is the time when the initial request was enqueued
	enqueueTime time.Time
}

func (request Request) GetMaxRetries(workerDefault uint) uint {
	if request.maxRetries != nil {
		return *request.maxRetries
	}
	return workerDefault
}

func (worker *RequestWorker) DisableUDP() {
	if worker.disableTCP {
		panic("It is not allowed to disable both TCP an UDP")
	}
	worker.disableUDP = true
}

func (worker *RequestWorker) DisableTCP() {
	if worker.disableUDP {
		panic("It is not allowed to disable both TCP an UDP")
	}
	worker.disableTCP = true
}

func (worker *RequestWorker) Dequeue(ctx common.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			response := worker.client.Dequeue(ctx)

			// process response will post the response into the corresponding responseChannel
			// it needs to run in a go-routine, because if the responseChannel blocks,
			// it would stall the entire program.
			ctx.Go(func() { worker.processResponse(response) })
		}
	}
}

func (worker *RequestWorker) processResponse(response client.Response) {
	rawEntry, ok := worker.correlationMap.LoadAndDelete(response.CorrelationId)

	if !ok {
		worker.log.Warn().
			Interface("response", response).
			Msg("Uncorrelated request")
		return
	}

	entry := rawEntry.(correlationMapEntry)

	shouldRetry := response.Message == nil || // If we get no message, we retry
		response.Message != nil && !response.TCP && response.Message.Truncated || // If we used TCP and get a truncated message, we stop (probably not going to get any better)
		response.Message != nil && isRetryable(response.Message.Rcode) // Everything except format error is not retryable - stop

	// If we get formErr but have already disabled EDNS0, we might stop as well
	if response.Message != nil && response.Message.Rcode == client.RcodeFormatError && entry.request.disableEDNS0 {
		shouldRetry = false
	}

	stop := entry.retryCount >= entry.request.GetMaxRetries(worker.maxRetries) || !shouldRetry // If we reached maxRetries, we stop

	msgEx := toMessageExchange(response,
		entry.request.parentCorrelationId,
		entry.request.nameServerIP,
		entry.request.question,
		entry.enqueueTime,
		false,
		entry.retryCount,
		response.TCP,
		stop)

	if !entry.request.disableInfraCache {
		worker.infraCache.Track(msgEx)
	}

	Metrics.TrackResponse(msgEx, stop)

	if stop {
		// Only cache finished messages.
		worker.cache.Set(msgEx)
	}

	if err := entry.request.responseQueue.Enqueue(Response{
		carryOverArgs:  entry.request.data,
		nameServerName: entry.request.nameServerName,
		msgExchange:    msgEx,
	}); err != nil {
		panic(err) // Queue should never be locked
	}

	if stop {
		return
	}

	// else !stop => do a retry
	backOff := worker.infraCache.GetBackoff(entry.request.nameServerIP)

	// Try cache lookup immediately - maybe the answer is already there.
	if !entry.request.skipCache && worker.respondFromCache(response.CorrelationId, entry.retryCount+1, entry.request) {
		return
	}

	time.AfterFunc(backOff, func() {
		var status serverStatus
		status.udpResponsive, status.tcpResponsive, status.reason = worker.infraCache.IsResponsive(entry.request.nameServerIP)
		truncated := false
		rcode := -1
		if msgEx.Message != nil {
			truncated = msgEx.Message.Truncated
			rcode = msgEx.Message.Rcode
		}

		worker.enqueue(response.CorrelationId,
			entry.request,
			entry.retryCount+1,
			worker.disableEDNS0Actual(rcode, truncated, response.TCP),
			worker.useTCPActual(response.TCP, entry.request.disableTCPFallback, entry.retryCount+1, truncated, status),
			status)
	})
}

func (worker *RequestWorker) useTCPActual(lastRequestUsedTCP bool, requestDisableTCPFallback bool, retryIdx uint, isTruncated bool, status serverStatus) bool {
	// If TCP is globally disabled/enabled, it overwrites everything else
	if worker.disableTCP {
		return false
	}
	if worker.disableUDP {
		return true
	}
	if requestDisableTCPFallback {
		return false
	}

	// else, we have the choice between TCP/UDP

	// On truncation, use TCP because nothing else makes sense
	// If the server is not TCP responsive, the infrastructure cache will answer with "SERVER_UNRESPONSIVE"
	if isTruncated {
		return true
	}

	// On the last two tries, always try TCP
	// If the server is not TCP responsive, the infrastructure cache will answer with "SERVER_UNRESPONSIVE"
	// and the last two tries will be skipped.
	if retryIdx >= worker.maxRetries-1 {
		return true
	}

	// Once switched to TCP, stick with it
	// Otherwise we might get a truncated message again
	if lastRequestUsedTCP {
		return true
	}

	// If it is unresponsive to UDP, use TCP
	if !status.udpResponsive {
		return true
	}

	// no cases apply, use UDP
	return false
}

func (worker *RequestWorker) disableEDNS0Actual(rcode int, isTruncated bool, isTCP bool) bool {
	// If the response is FormatError it might be due to EDNS0, disable it.
	if rcode == client.RcodeFormatError {
		return true
	}

	// If the truncated bit is set even though we used TCP, it might be because the server (incorrectly) truncates responses based on EDNS (see rfc8906)
	if isTruncated && isTCP {
		return true
	}

	return false
}

func (worker *RequestWorker) Enqueue(request Request) {
	var status serverStatus
	status.udpResponsive, status.tcpResponsive, status.reason = worker.infraCache.IsResponsive(request.nameServerIP)

	useTCPActual := worker.useTCPActual(false, request.disableTCPFallback, 0, false, status)

	worker.enqueue(snowflake.ID(), request, 0, request.disableEDNS0, useTCPActual, status)
}

func (worker *RequestWorker) enqueue(correlationId uint64, request Request, retryCount uint, disableEDNS0 bool, useTCP bool, status serverStatus) {
	// This call is on a very hot path
	// We deliberately not use a CounterVec here, because it is more expensive on the CPU
	Metrics.QueriesSent.Inc()

	// If cache entry is there, respond right away
	if !request.skipCache && worker.respondFromCache(correlationId, retryCount, request) {
		return
	}

	// If cache entry is there, respond right away
	if worker.respondFromInfraCache(correlationId, retryCount, request, status, useTCP) {
		return
	}

	if DoNotScanList.MustNotScan(request.question, request.nameServerName, request.nameServerIP) {
		if err := request.responseQueue.Enqueue(Response{
			carryOverArgs:  request.data,
			nameServerName: request.nameServerName,
			msgExchange: model.MessageExchange{
				OriginalQuestion: request.question,
				NameServerIP:     request.nameServerIP,
				Metadata: model.Metadata{
					FromCache:     false,
					RetryIdx:      0,
					TCP:           useTCP,
					CorrelationId: correlationId,
					EnqueueTime:   time.Now(),
					DequeueTime:   time.Now(),
					IsFinal:       true,
				},
				Error: &model.SendError{
					Code: model.ErrorCodeDoNotScan,
				},
			},
		}); err != nil {
			panic(err)
		}

		return
	}

	worker.correlationMap.Store(correlationId, correlationMapEntry{
		request:     request,
		retryCount:  retryCount,
		enqueueTime: time.Now().UTC(),
	})

	worker.client.Enqueue(correlationId, toQuestion(request.question), request.nameServerIP,
		client.If(useTCP, client.UseTCP()),
		client.If(disableEDNS0, client.DisableEDNSO()),
		client.SetDO(request.do),
		client.LogTo(request.log))
}

func (worker *RequestWorker) respondFromCache(correlationId uint64,
	retryIndex uint,
	request Request) bool {

	// If cache entry is there, respond right away
	if msg, exists := worker.cache.Get(request.nameServerIP, request.question); exists {
		msg.Metadata.CorrelationId = correlationId
		msg.Metadata.RetryIdx = retryIndex

		if err := request.responseQueue.Enqueue(Response{
			carryOverArgs:  request.data,
			nameServerName: request.nameServerName,
			msgExchange:    msg,
		}); err != nil {
			panic(err)
		}

		return true
	}

	return false
}

func (worker *RequestWorker) respondFromInfraCache(correlationId uint64,
	retryIndex uint,
	request Request,
	status serverStatus,
	useTCPActual bool) bool {

	// name server is not responsive to TCP
	if !status.tcpResponsive && useTCPActual {
		if err := request.responseQueue.Enqueue(Response{
			carryOverArgs:  request.data,
			nameServerName: request.nameServerName,
			msgExchange:    unresponsiveMessageExchange(request.question, request.nameServerIP, status.reason, correlationId, useTCPActual, retryIndex),
		}); err != nil {
			panic(err)
		}

		return true
	}

	// name server is not responsive to UDP
	if !status.udpResponsive && !useTCPActual {
		if err := request.responseQueue.Enqueue(Response{
			carryOverArgs:  request.data,
			nameServerName: request.nameServerName,
			msgExchange:    unresponsiveMessageExchange(request.question, request.nameServerIP, status.reason, correlationId, useTCPActual, retryIndex),
		}); err != nil {
			panic(err)
		}

		return true
	}

	return false
}

func toQuestion(q model.Question) client.Question {
	return client.Question{
		Name:  string(q.Name),
		Type:  q.Type,
		Class: q.Class,
	}
}

func unresponsiveMessageExchange(q model.Question, ip netip.Addr, reason string, correlationId uint64, useTCP bool, retryIdx uint) model.MessageExchange {
	return model.MessageExchange{
		OriginalQuestion: q,
		NameServerIP:     ip,
		Metadata: model.Metadata{
			FromCache:     true,
			RetryIdx:      retryIdx,
			TCP:           useTCP,
			CorrelationId: correlationId,
			EnqueueTime:   time.Now(),
			DequeueTime:   time.Now(),
			IsFinal:       true,
		},
		Error: &model.SendError{
			Message: reason,
			Code:    "SERVER_UNRESPONSIVE",
		},
	}
}

func toMessageExchange(response client.Response,
	parentCorrelationId uint64,
	nameServerIp netip.Addr,
	originalQ model.Question,
	enqueueTime time.Time,
	fromCache bool,
	retryIdx uint,
	useTCP bool,
	isFinal bool) model.MessageExchange {

	ex := model.MessageExchange{
		OriginalQuestion: originalQ,
		ResponseAddr:     response.ResponseAddr,
		NameServerIP:     nameServerIp,
		Metadata: model.Metadata{
			FromCache:     fromCache,
			RetryIdx:      retryIdx,
			ConnId:        response.ConnId,
			TCP:           useTCP,
			EnqueueTime:   enqueueTime,
			DequeueTime:   time.Now().UTC(),
			CorrelationId: response.CorrelationId,
			ParentId:      parentCorrelationId,
			RTT:           response.RTT,
			IsFinal:       isFinal,
		},
		Message: response.Message,
	}

	if response.Error != nil {
		ex.Error = &model.SendError{
			Message: response.Error.Error(),
			Code:    model.ErrorCodeSendError,
		}
	}

	return ex
}

func isRetryable(rcode int) bool {
	return rcode == client.RcodeServerFailure || rcode == client.RcodeFormatError
}
