package test

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"sync/atomic"
)

var _ client.DNSClientDecorator = new(MockClient)

// MockClient is a customizable mock implementation of common.DNSClientDecorator to be used for testing.
type MockClient struct {
	ReceivedCalls int32
	ExchangeFunc  func(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts)
	RespChan      chan client.Response
}

func (mock *MockClient) Enqueue(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts) {
	atomic.AddInt32(&mock.ReceivedCalls, 1)

	if mock.ExchangeFunc != nil {
		mock.ExchangeFunc(correlationId, q, ip, sendOpts)
	}
}

func (mock *MockClient) ResponseChan() <-chan client.Response {
	return mock.RespChan
}
