package tcp

import (
	"encoding/binary"
	"errors"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"github.com/godruoyi/go-snowflake"
	"github.com/miekg/dns"
	"net"
	"os"
	"testing"
	"time"
)

type MockPool struct {
	getOrCreateFunc     func(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error)
	createEphemeralFunc func(remoteIP client.Address, remotePort uint16) (*PooledConn, error)
}

func (p MockPool) GetOrCreate(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
	return p.getOrCreateFunc(remoteIP, remotePort, onReceive)
}

func (p MockPool) CreateEphemeral(remoteIP client.Address, remotePort uint16) (*PooledConn, error) {
	return p.createEphemeralFunc(remoteIP, remotePort)
}

func TestClient_CanEnqueueAndReceive(t *testing.T) {
	corrId := snowflake.ID()
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	internal.NewId = func() uint16 { return responseMsg.Id }
	remoteAddr := test.MockAddr{}.NewRandom()
	remotePort := uint16(332)

	writeCalls := 0
	writer := test.MockConn{
		WriteFunc: func(bytes []byte) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
	}
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return writer, nil
	}
	conn := newPooledConn(remoteAddr, remotePort)

	c := NewClient(MockPool{
		getOrCreateFunc: func(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
			_ = conn.DialOnce(time.Second)
			time.AfterFunc(100*time.Millisecond, func() { onReceive(conn, responseMsg, "1.2.3.4:53", nil) })
			return conn, nil
		},
	}, time.Minute, 0)

	q := client.Question{}

	c.Enqueue(corrId, q, remoteAddr, client.DefaultSendOpts)

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

func TestClient_CanReceiveUnsolicitedMessage(t *testing.T) {
	corrId := snowflake.ID()
	unsolicitedResponseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	unsolicitedResponseMsg.Id = 1111
	remoteAddr := test.MockAddr{}.NewRandom()
	remotePort := uint16(332)

	writeCalls := 0
	writer := test.MockConn{
		WriteFunc: func(bytes []byte) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
	}
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return writer, nil
	}
	conn := newPooledConn(remoteAddr, remotePort)

	c := NewClient(MockPool{
		getOrCreateFunc: func(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
			_ = conn.DialOnce(time.Second)
			time.AfterFunc(100*time.Millisecond, func() { onReceive(conn, unsolicitedResponseMsg, "1.2.3.4:53", nil) })
			return conn, nil
		},
	}, time.Minute, 0)

	c.Enqueue(corrId, client.Question{}, remoteAddr, client.DefaultSendOpts)

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

func TestClient_PoolExhausted_FallbackToEphemeral(t *testing.T) {
	corrId := snowflake.ID()
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	internal.NewId = func() uint16 { return responseMsg.Id }
	remoteAddr := test.MockAddr{}.NewRandom()
	remotePort := uint16(332)

	writeCalls := 0
	readCalls := 0
	writer := test.MockConn{
		WriteFunc: func(bytes []byte) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
		ReadFunc: func(bytes []byte) (int, error) {
			p, _ := responseMsg.Pack()
			if readCalls == 0 {
				binary.BigEndian.PutUint16(bytes, uint16(len(p)))
				readCalls++
				return 2, nil
			}
			copy(bytes, p)
			return len(p), nil
		},
	}
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return writer, nil
	}
	conn := newPooledConn(remoteAddr, remotePort)

	c := NewClient(MockPool{
		getOrCreateFunc: func(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
			return nil, client.ErrPoolExhausted
		},
		createEphemeralFunc: func(remoteIP client.Address, remotePort uint16) (*PooledConn, error) {
			_ = conn.DialOnce(time.Second)
			return conn, nil
		},
	}, time.Minute, 0)

	c.Enqueue(corrId, client.Question{}, remoteAddr, client.DefaultSendOpts)

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

func TestClient_SendErr_FallbackToEphemeral(t *testing.T) {
	corrId := snowflake.ID()
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	internal.NewId = func() uint16 { return responseMsg.Id }
	remoteAddr := test.MockAddr{}.NewRandom()
	remotePort := uint16(332)

	writeCalls := 0
	readCalls := 0
	writer := test.MockConn{
		WriteFunc: func(bytes []byte) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
		ReadFunc: func(bytes []byte) (int, error) {
			p, _ := responseMsg.Pack()
			if readCalls == 0 {
				binary.BigEndian.PutUint16(bytes, uint16(len(p)))
				readCalls++
				return 2, nil
			}
			copy(bytes, p)
			return len(p), nil
		},
	}
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return writer, nil
	}
	goodConn := newPooledConn(remoteAddr, remotePort)
	faultyConn := newPooledConn(remoteAddr, remotePort)

	c := NewClient(MockPool{
		getOrCreateFunc: func(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
			_ = faultyConn.DialOnce(time.Second)
			time.AfterFunc(100*time.Millisecond, func() { onReceive(faultyConn, nil, "1.2.3.4:53", errors.New("connection terminated")) })
			return faultyConn, nil
		},
		createEphemeralFunc: func(remoteIP client.Address, remotePort uint16) (*PooledConn, error) {
			_ = goodConn.DialOnce(time.Second)
			return goodConn, nil
		},
	}, time.Minute, 0)

	c.Enqueue(corrId, client.Question{}, remoteAddr, client.DefaultSendOpts)

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

func TestClient_Timeout(t *testing.T) {
	tcpTimeout := 250 * time.Millisecond
	expectedTimeout := 2 * tcpTimeout // twice because we can have a ephemeral fallback
	corrId := snowflake.ID()
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	internal.NewId = func() uint16 { return responseMsg.Id }
	remoteAddr := test.MockAddr{}.NewRandom()
	remotePort := uint16(332)
	closeCalled := false
	ephConnCloseCalled := false

	writeCalls := 0
	writer := test.MockConn{
		WriteFunc: func(bytes []byte) (int, error) {
			writeCalls++
			return len(bytes), nil
		},
		ReadFunc: func(bytes []byte) (int, error) {
			time.Sleep(tcpTimeout)
			return 0, os.ErrDeadlineExceeded
		},
	}
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return writer, nil
	}
	conn := newPooledConn(remoteAddr, remotePort)
	conn.onClose = func() {
		closeCalled = true
	}

	ephConn := newPooledConn(remoteAddr, remotePort)
	ephConn.onClose = func() {
		ephConnCloseCalled = true
	}

	c := NewClient(MockPool{
		getOrCreateFunc: func(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
			_ = conn.DialOnce(time.Second)
			return conn, nil
		},
		createEphemeralFunc: func(remoteIP client.Address, remotePort uint16) (*PooledConn, error) {
			_ = ephConn.DialOnce(time.Second)
			return ephConn, nil
		},
	}, tcpTimeout, 0)

	start := time.Now()
	c.Enqueue(corrId, client.Question{}, remoteAddr, client.DefaultSendOpts)
	response := <-c.ResponseChan()
	duration := time.Since(start)

	if expectedTimeout-50*time.Millisecond > duration || duration > expectedTimeout+50*time.Millisecond {
		t.Errorf("Expected timeout to occur after %v +- 50ms, got %v", expectedTimeout, duration)
	}
	if response.CorrelationId != corrId {
		t.Errorf("Expected response.CorrelationId to be %v, got %v", corrId, response.CorrelationId)
	}

	var err client.Error
	if !errors.As(response.Error, &err) || err.Code != client.ErrorCodeReceiveTimeout {
		t.Errorf("Expected response.Error to be %v, got %v", client.ErrorCodeReceiveTimeout, response.Error)
	}
	if !closeCalled {
		t.Errorf("Expected pooled connection to be closed")
	}
	if !ephConnCloseCalled {
		t.Errorf("Expected ephemeral connection to be closed")
	}
}
