package udp

import (
	"errors"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"github.com/godruoyi/go-snowflake"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

type MockPool struct {
	callback func(onReceive ReceiveCallback) (*PooledConn, error)
}

func (p MockPool) GetOrCreate(onReceive ReceiveCallback) (*PooledConn, error) {
	return p.callback(onReceive)
}

func TestClient_CanEnqueueAndReceive(t *testing.T) {
	corrId := snowflake.ID()
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	internal.NewId = func() uint16 { return responseMsg.Id }

	writeCalls := 0
	writer := test.MockPacketConn{
		WriteToFunc: func(bytes []byte, addr net.Addr) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
		SetWriteDeadlineFunc: func(t time.Time) error {
			return nil
		},
	}

	ip := test.MockAddr{Value: "1.2.3.4"}

	conn := newPooledUDPConn(1232, false, writer)
	c := NewClient(MockPool{
		callback: func(onReceive ReceiveCallback) (*PooledConn, error) {
			time.AfterFunc(100*time.Millisecond, func() { onReceive(conn.Id, responseMsg, "1.2.3.4:53", nil) })
			return conn, nil
		},
	}, MockPool{}, time.Minute, 1232)

	q := client.Question{}

	c.Enqueue(corrId, q, ip, client.DefaultSendOpts)

	response := <-c.ResponseChan()

	if response.CorrelationId != corrId {
		t.Errorf("Expected response.CorrelationId to be %v, got %v", corrId, response.CorrelationId)
	}

	if response.Message.Question[0].Name != responseMsg.Question[0].Name {
		t.Errorf("Expected response.Msg to be %v, got %v", responseMsg, response.Message)
	}

	if response.Error != nil {
		t.Errorf("Expected response.Error to be nil, got %v", response.Error)
	}
}

func TestClient_CanTimeout(t *testing.T) {
	expectedTimeout := 500 * time.Millisecond
	corrId := snowflake.ID()
	writeCalls := 0
	writer := test.MockPacketConn{
		WriteToFunc: func(bytes []byte, addr net.Addr) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
		SetWriteDeadlineFunc: func(t time.Time) error {
			return nil
		},
	}
	conn := newPooledUDPConn(1232, false, writer)
	c := NewClient(MockPool{
		callback: func(onReceive ReceiveCallback) (*PooledConn, error) {
			return conn, nil
		},
	}, MockPool{}, expectedTimeout, 1232)

	ip := new(test.MockAddr).NewRandomV4()
	start := time.Now()

	c.Enqueue(corrId, client.Question{}, ip, client.DefaultSendOpts)
	response := <-c.ResponseChan()

	duration := time.Since(start)

	if expectedTimeout-50*time.Millisecond > duration || duration > expectedTimeout+50*time.Millisecond {
		t.Errorf("Expected timeout to occur after %v +- 50ms, got %v", expectedTimeout, duration)
	}

	if response.CorrelationId != corrId {
		t.Errorf("Expected response.CorrelationId to be %v, got %v", corrId, response.CorrelationId)
	}

	if !errors.Is(response.Error, client.ErrReceiveTimeout) {
		t.Errorf("Expected response.Error to be timeout, got %v", response.Error)
	}
}

func TestClient_CanReceiveUnsolicitedMessage(t *testing.T) {
	corrId := snowflake.ID()

	unsolicitedResponseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	unsolicitedResponseMsg.Id = 1111
	internal.NewId = func() uint16 { return 2222 }

	writeCalls := 0
	writer := test.MockPacketConn{
		WriteToFunc: func(bytes []byte, addr net.Addr) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
		SetWriteDeadlineFunc: func(t time.Time) error {
			return nil
		},
	}
	conn := newPooledUDPConn(1232, false, writer)
	c := NewClient(MockPool{
		callback: func(onReceive ReceiveCallback) (*PooledConn, error) {
			time.AfterFunc(100*time.Millisecond, func() { onReceive(conn.Id, unsolicitedResponseMsg, "1.2.3.4:53", nil) })
			return conn, nil
		},
	}, MockPool{}, time.Minute, 1232)

	q := client.Question{}
	ip := new(test.MockAddr).NewRandomV4()
	c.Enqueue(corrId, q, ip, client.DefaultSendOpts)

	response := <-c.ResponseChan()

	if response.CorrelationId != 0 {
		t.Errorf("Expected response.CorrelationId to be %v, got %v", corrId, response.CorrelationId)
	}

	if response.Message.Question[0].Name != unsolicitedResponseMsg.Question[0].Name {
		t.Errorf("Expected response.Msg to be %v, got %v", unsolicitedResponseMsg, response.Message)
	}

	if response.Error != nil {
		t.Errorf("Expected response.Error to be nil, got %v", response.Error)
	}
}
