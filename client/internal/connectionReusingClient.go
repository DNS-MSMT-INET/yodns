package internal

import (
	"context"
	"github.com/DNS-MSMT-INET/yodns/client"
)

var _ client.DNSClientDecorator = new(ConnectionReusingClient)

// ConnectionReusingClient does a fan-out by sending UDP requests to a udp.Client and tcp requests to a tcp.Client.
// It fans-in the responses and exposes them via ResponseChan()
type ConnectionReusingClient struct {
	UDPClient client.DNSClientDecorator
	TCPClient client.DNSClientDecorator

	responseChan chan client.Response
}

func NewReusingClient(udpClient client.DNSClientDecorator, tcpClient client.DNSClientDecorator) *ConnectionReusingClient {
	return &ConnectionReusingClient{
		TCPClient:    tcpClient,
		UDPClient:    udpClient,
		responseChan: make(chan client.Response, DefaultResponseChannelBuffer),
	}
}

func (c *ConnectionReusingClient) Start(ctx context.Context) *ConnectionReusingClient {
	go c.mergeWorker(ctx)
	return c
}

func (c *ConnectionReusingClient) ResponseChan() <-chan client.Response {
	return c.responseChan
}

func (c *ConnectionReusingClient) Enqueue(correlationId uint64, q client.Question, ip client.Address, sendOpts client.SendOpts) {
	if sendOpts.UseTCP {
		c.TCPClient.Enqueue(correlationId, q, ip, sendOpts)
	} else {
		c.UDPClient.Enqueue(correlationId, q, ip, sendOpts)
	}
}

func (c *ConnectionReusingClient) mergeWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case udp := <-c.UDPClient.ResponseChan():
			c.responseChan <- udp
		case tcp := <-c.TCPClient.ResponseChan():
			c.responseChan <- tcp
		}
	}
}
