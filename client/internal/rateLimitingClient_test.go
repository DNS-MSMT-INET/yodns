package internal

import (
	"context"
	"errors"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"github.com/godruoyi/go-snowflake"
	"github.com/rs/zerolog"
	"net/netip"
	"testing"
	"time"
)

func TestRateLimitingClient_Enqueue_RateLimitInflight(t *testing.T) {
	maxAllowedCalls := 1
	mock := getMock(100 * time.Millisecond)
	c := NewClient(&mock, 1000, int64(maxAllowedCalls), 5*time.Second, zerolog.Logger{}).Start(context.Background())
	nsIP := new(test.MockAddr).NewRandom()

	// Call it one more time than allowed.
	for i := 0; i < maxAllowedCalls+1; i++ {
		go c.Enqueue(snowflake.ID(), client.Question{}, nsIP, client.SendOpts{})
	}

	// After 50ms, the calls from the inner c have not returned yet.
	time.Sleep(50 * time.Millisecond)

	// maxAllowedCalls should have been made.
	if mock.ReceivedCalls != int32(maxAllowedCalls) {
		t.Errorf("RateLimitingdnsClient.Enqueue() issued %v concurrent calls to the inner c although only %v are allowed",
			mock.ReceivedCalls, maxAllowedCalls)
		return
	}

	// Wait a bit. The calls should return and the third call should be issued.
	time.Sleep(80 * time.Millisecond)

	if mock.ReceivedCalls != int32(maxAllowedCalls+1) {
		t.Errorf("RateLimitingdnsClient.Enqueue() did not issue all %v calls to the inner c evenutally",
			maxAllowedCalls+1)
		return
	}
}

func TestRateLimitingClient_Enqueue_RateLimitPerSecond(t *testing.T) {
	maxAllowedCalls := 3
	tokenBucketSize := 5
	mock := getMock(100 * time.Millisecond)
	c := NewClient(&mock, 1, 1000, 5*time.Second, zerolog.Logger{}).Start(context.Background())
	nsIP := new(test.MockAddr).NewRandom()

	// Call it one more time than allowed.
	for i := 0; i < tokenBucketSize+maxAllowedCalls; i++ {
		go c.Enqueue(snowflake.ID(), client.Question{}, nsIP, client.SendOpts{})
	}

	// After 50ms, the calls from the inner c have not returned yet.
	time.Sleep(50 * time.Millisecond)

	// maxAllowedCalls should have been made.
	if int(mock.ReceivedCalls) != tokenBucketSize {
		t.Errorf("RateLimitingdnsClient.Enqueue() issued %v calls to the inner c although only %v are allowed", mock.ReceivedCalls, tokenBucketSize)
		return
	}

	time.Sleep(time.Second)

	if int(mock.ReceivedCalls) != tokenBucketSize+1 {
		t.Errorf("RateLimitingdnsClient.Enqueue() issued %v calls to the inner c although only %v are allowed", mock.ReceivedCalls, tokenBucketSize+1)
		return
	}

	time.Sleep(time.Second)

	if int(mock.ReceivedCalls) != tokenBucketSize+2 {
		t.Errorf("RateLimitingdnsClient.Enqueue() issued %v calls to the inner c although only %v are allowed", mock.ReceivedCalls, tokenBucketSize+2)
		return
	}
}

// TestRateLimitingClient_Enqueue_RateLimitPerSecond_FailEarly
// tests that the rate limiter will fail a query early, if the limit cannot be reached within the specified time.
func TestRateLimitingClient_Enqueue_RateLimitPerSecond_FailEarly(t *testing.T) {
	mock := getMock(100 * time.Millisecond)
	c := NewClient(&mock, 1, 1000, 2*time.Second, zerolog.Logger{}).Start(context.Background())
	nsIP := new(test.MockAddr).NewRandom()

	// Call it three times to fill the rate-limiter
	for i := 0; i < 7; i++ { // Remember the token bucket size
		go c.Enqueue(snowflake.ID(), client.Question{}, nsIP, client.SendOpts{})
	}
	time.Sleep(time.Millisecond)

	start := time.Now()
	c.Enqueue(snowflake.ID(), client.Question{}, nsIP, client.SendOpts{})
	resp := <-c.ResponseChan()
	duration := time.Since(start)

	if duration > time.Millisecond {
		t.Errorf("Expected the rate limiter to fail instantly, but it took %v", duration)
	}
	if !errors.Is(resp.Error, client.ErrPredicatedRateLimitTimeout) {
		t.Errorf("Expected %v, got %v", client.ErrPredicatedRateLimitTimeout, resp.Error)
	}
}

// We assert that Exchange is blocking in order to put some backpressure on the system if the client can't keep up
func TestRateLimitingClient_Enqueue_IsBlocking(t *testing.T) {
	mock := getMock(200 * time.Millisecond)
	c := NewClient(&mock, 100, 1, time.Second, zerolog.Logger{}).Start(context.Background())

	nsIP := new(test.MockAddr).NewRandom()

	go c.Enqueue(snowflake.ID(), client.Question{}, nsIP, client.SendOpts{})
	time.Sleep(time.Millisecond) // Make sure the go routine has called before continuing

	// second call should be blocked
	start := time.Now()
	c.Enqueue(snowflake.ID(), client.Question{}, nsIP, client.SendOpts{})
	duration := time.Since(start)

	if 180*time.Millisecond > duration || 220*time.Millisecond < duration {
		t.Errorf("Enqueue should be a blocking operation and take approximately 200ms but it took %v", duration)
	}
}

func TestRateLimitingClient_Enqueue_UnsolicitedMessage(t *testing.T) {
	mock := getMock(100 * time.Millisecond)
	c := NewClient(&mock, 1, 1, time.Second, zerolog.Logger{}).Start(context.Background())

	expectedResponse := client.Response{
		CorrelationId: 0,
		NameServerIP:  netip.MustParseAddr("1.2.3.4"),
	}
	mock.RespChan <- expectedResponse

	receivedResponse := <-c.ResponseChan()

	if expectedResponse.NameServerIP != receivedResponse.NameServerIP {
		t.Errorf("Expected %v, got %v", expectedResponse, receivedResponse)
	}
}

func getMock(sleepBeforeReturn time.Duration) test.MockClient {
	c := test.MockClient{
		RespChan: make(chan client.Response, 1),
	}

	c.ExchangeFunc = func(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts) {
		time.AfterFunc(sleepBeforeReturn, func() {
			c.RespChan <- client.Response{
				CorrelationId: correlationId,
				NameServerIP:  ip,
			}
		})
	}

	return c
}
