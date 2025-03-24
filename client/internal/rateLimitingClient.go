package internal

import (
	"context"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
	"sync"
	"sync/atomic"
	"time"
)

var _ client.DNSClientDecorator = new(RateLimitingClient)

var ErrUnkownKey = fmt.Errorf("unkown key")

const (
	// DefaultBurstSize specifies the burst size for the token bucket rate limiter.
	// Even a small burst size suffices to make the performance much better in certain cases
	DefaultBurstSize = 5
)

// RateLimitingClient ensures that the total number of concurrent requests
// as well as the concurrent requests per server are limited.
type RateLimitingClient struct {
	innerClient              client.DNSClientDecorator
	maxInflightPerIP         int64
	maxQueriesPerSecondPerIP int64

	// This is the maximum timeout that the client can delay a request.
	rateLimitTimeout time.Duration

	limitMap atomic.Value

	responseChan chan client.Response

	log zerolog.Logger
}

// Helper struct for atomic swap operations
type maps struct {
	Current *sync.Map
	Stale   *sync.Map
}

type rateLimitEntry struct {
	// sem counts the number of queries inflight
	sem *semaphore.Weighted

	// limit is responsible for the "per second" rate limiting
	limit *rate.Limiter
}

func (e *rateLimitEntry) wait(ctx context.Context) error {
	// Make a reservation for the query
	r := e.limit.Reserve()
	if !r.OK() {
		return client.ErrImpossibleRateLimit
	}

	// If the deadline is before the reservation allows us to send the query, we fail immediately
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(time.Now().Add(r.Delay())) {
		r.Cancel()
		return client.ErrPredicatedRateLimitTimeout
	}

	// Now wait for a place with the max-inflight rate limiting
	// We're basically waiting for the max-inflight and the reservation in parallel.
	timer := prometheus.NewTimer(client.Metrics.RateLimitWaitTime.With(prometheus.Labels{"type": "inflight"}))
	err := e.sem.Acquire(ctx, 1)
	timer.ObserveDuration()
	if err != nil {
		return client.ErrRateLimitTimeout
	}

	// Now wait for the remaining time of the reservation
	d := r.Delay()
	client.Metrics.RateLimitWaitTime.With(prometheus.Labels{"type": "time"}).Observe(d.Seconds())
	t := time.NewTimer(d)
	select {
	case <-ctx.Done():
		t.Stop()
		return client.ErrRateLimitTimeout
	case <-t.C:
	}

	return nil
}

func NewClient(innerClient client.DNSClientDecorator,
	maxQueriesPerSecondPerIP int64,
	maxInflightPerIP int64,
	rateLimitTimeout time.Duration,
	log zerolog.Logger) *RateLimitingClient {
	c := RateLimitingClient{
		innerClient:              innerClient,
		maxInflightPerIP:         maxInflightPerIP,
		maxQueriesPerSecondPerIP: maxQueriesPerSecondPerIP,
		rateLimitTimeout:         rateLimitTimeout,
		responseChan:             make(chan client.Response, DefaultResponseChannelBuffer),
		log:                      log,
	}

	c.limitMap.Store(maps{
		Current: new(sync.Map),
		Stale:   new(sync.Map),
	})

	return &c
}

func (c *RateLimitingClient) Start(ctx context.Context) *RateLimitingClient {
	go c.releaseLockWorker(ctx)
	go c.swapWorker(ctx)
	return c
}

func (c *RateLimitingClient) ResponseChan() <-chan client.Response {
	return c.responseChan
}

func (c *RateLimitingClient) Enqueue(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts) {
	ctx, cancel := context.WithTimeout(context.Background(), c.rateLimitTimeout)
	defer cancel()

	err := c.acquireRateLimit(ctx, ip)

	if err != nil {
		sendOpts.Log.Err(err).
			Msg("rate limit timeout")

		c.responseChan <- ErrorResponse(correlationId, 0, ip, "", 0, sendOpts.UseTCP, err)
		return
	}

	client.Metrics.QueriesInflight.Inc()
	c.innerClient.Enqueue(correlationId, q, ip, sendOpts)
}

// releaseLockWorker releases the locks after requests return, so new requests can enter the critical section
func (c *RateLimitingClient) releaseLockWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case response := <-c.innerClient.ResponseChan():
			// If correlationId == 0, that means we have an unsolicited message.
			// Most likely a response that was received after the timeout expired,
			// but it can also happen if a nameserver sends a message that was not requested
			if response.CorrelationId != 0 {
				if err := c.releaseRateLimitKey(response.NameServerIP); err != nil {
					c.log.Err(err).
						Interface("response", response).
						Msgf("failed to release rate limit")
				}

				client.Metrics.QueriesInflight.Dec()
			}

			// Maybe we want this in a go routine to not block the release worker?
			// On the other hand, it applies backpressure, because enqueueing will be throttled - which is good.
			c.responseChan <- response
		}
	}
}

func (c *RateLimitingClient) acquireRateLimit(ctx context.Context, key any) error {
	limitMap, ok := c.limitMap.Load().(maps)
	if !ok { // If it happens, we have a bug
		panic("unexpected type in limitMap")
	}

	// First, check if we can find the entry in the stale map
	staleEntry, loaded := limitMap.Stale.Load(key)
	if !loaded {
		staleEntry = &rateLimitEntry{
			sem:   semaphore.NewWeighted(c.maxInflightPerIP),
			limit: rate.NewLimiter(rate.Limit(c.maxQueriesPerSecondPerIP), DefaultBurstSize),
		}
	}

	// Then, get the entry from the current map - if there is none, add the stale entry.
	currentEntry, _ := limitMap.Current.LoadOrStore(key, staleEntry)
	entry, ok := currentEntry.(*rateLimitEntry)
	if !ok { // If it happens, we have a bug
		panic("unexpected type of entry in semaphore map")
	}

	// Wait for the queries inflight limit to be honored
	return entry.wait(ctx)
}

func (c *RateLimitingClient) releaseRateLimitKey(key any) error {
	limitMap, ok := c.limitMap.Load().(maps)
	if !ok { // If it happens, we have a bug
		panic("unexpected type in limitMap")
	}

	// Cases:
	// - entry coming back which only exists in current
	// - entry coming back that only exists in stale
	//		- either it was swapped from current to stale
	//		- or it was added in the moment of the swap and was added directly to stale
	// - entry coming back that exists in current and stale

	loadedEntry, loaded := limitMap.Current.Load(key)
	if loaded {
		entry, ok := loadedEntry.(*rateLimitEntry)
		if !ok { // If it happens, we have a bug
			panic("unexpected type of entry in semaphore map")
		}

		releaseSem(entry.sem, c.log, true)
		return nil
	}

	loadedEntry, loaded = limitMap.Stale.Load(key)
	if loaded {
		entry, ok := loadedEntry.(*rateLimitEntry)
		if !ok { // If it happens, we have a bug
			panic("unexpected type of entry in semaphore map")
		}

		releaseSem(entry.sem, c.log, false)
		return nil
	}

	return fmt.Errorf("'%v': %w", key, ErrUnkownKey)
}

func releaseSem(sem *semaphore.Weighted, log zerolog.Logger, current bool) {
	func() {
		defer func() {
			if r := recover(); r != nil {
				// This happens rarely. Might be a race condition.
				// However, it is not catastrophic, so we don't want to crash
				// If we find and fix it, we can remove this method.
				log.Error().Bool("isCurrent", current).Interface("err", r).Msgf("Semaphore released more than held")
			}
		}()
		sem.Release(1)
	}()
}

func (c *RateLimitingClient) swapWorker(ctx context.Context) {
	// swap interval must be longer than rateLimitTimeout + query timeout to avoid race conditions
	//nolint:mnd
	t := time.NewTicker(2 * c.rateLimitTimeout)
	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			oldMap, ok := c.limitMap.Load().(maps)
			if !ok { // If it happens, we have a bug
				panic("unexpected type in limitMap")
			}

			c.limitMap.Store(maps{
				Stale:   oldMap.Current,
				Current: new(sync.Map),
			})
		}
	}
}
