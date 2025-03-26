package udp

import (
	"errors"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"github.com/miekg/dns"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPooledUDPConn_ReceiveError_ExpectFaultyAndClose(t *testing.T) {
	wasClosed := false
	inner := test.MockPacketConn{
		CloseFunc: func() error {
			wasClosed = true
			return nil
		},
		ReadFromFunc: func(bytes []byte) (int, net.Addr, error) {
			return 0, nil, errors.New("failed")
		},
	}

	conn := newPooledUDPConn(512, false, inner)
	conn.StartReceiving(func(u uint64, msg *dns.Msg, s string, err error) {

	})
	time.Sleep(10 * time.Millisecond)

	if !wasClosed {
		t.Errorf("Expected inner connection to be closed")
	}
	if !conn.IsFaulty() {
		t.Errorf("Expect connection to be marked as faulty")
	}
}

func TestPooledUDPConn_SetDeadlineError_ExpectFaultyAndClose(t *testing.T) {
	wasClosed := false
	inner := test.MockPacketConn{
		CloseFunc: func() error {
			wasClosed = true
			return nil
		},
		SetWriteDeadlineFunc: func(t time.Time) error {
			return errors.New("failed")
		},
	}

	conn := newPooledUDPConn(512, true, inner)
	_ = conn.WriteMessageTo(new(dns.Msg), new(test.MockAddr).NewRandomV6(), 53, time.Second)
	time.Sleep(10 * time.Millisecond)

	if !wasClosed {
		t.Errorf("Expected inner connection to be closed")
	}
	if !conn.IsFaulty() {
		t.Errorf("Expect connection to be marked as faulty")
	}
}

func TestPooledUDPConn_WriteMessageTo(t *testing.T) {
	var receivedAddr net.Addr
	var receivedBytes []byte
	var receivedDeadline time.Time
	writer := test.MockPacketConn{
		WriteToFunc: func(p []byte, addr net.Addr) (int, error) {
			receivedBytes = p
			receivedAddr = addr
			return len(p), nil
		},
		SetWriteDeadlineFunc: func(t time.Time) error {
			receivedDeadline = t
			return nil
		},
	}

	conn := newPooledUDPConn(512, false, writer)

	msg := new(dns.Msg).SetQuestion("test.com.", 1)
	expectedBytes, _ := msg.Pack()
	expectedAddress := new(test.MockAddr).NewRandom()

	expectedDeadline := time.Now().Add(time.Minute)

	if err := conn.WriteMessageTo(msg, expectedAddress, 75, time.Minute); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !reflect.DeepEqual(receivedBytes, expectedBytes) {
		t.Errorf("Expected different messages body")
	}
	if receivedAddr.String() != internal.FormatWithPort(expectedAddress, 75) {
		t.Errorf("Expected address %v, got %v", expectedAddress, receivedAddr.String())
	}
	if expectedDeadline.Add(time.Millisecond).Before(receivedDeadline) || expectedDeadline.Add(-time.Millisecond).After(receivedDeadline) {
		t.Errorf("Expected received deadline to be close to %v, got %v", expectedDeadline, receivedDeadline)
	}
}

func TestPooledUDPConn_WriteMessageTo_ShortWrite_ExpectPanic(t *testing.T) {
	writer := test.MockPacketConn{
		WriteToFunc: func(p []byte, addr net.Addr) (int, error) {
			return 1, nil
		},
	}

	conn := newPooledUDPConn(512, false, writer)

	msg := new(dns.Msg).SetQuestion("test.com.", 1)

	defer func() {
		if rec := recover(); rec == nil {
			t.Errorf("Expected panic because of short write")
		}
	}()

	addr := new(test.MockAddr).NewRandom()
	_ = conn.WriteMessageTo(msg, addr, 53, time.Minute)
}

func TestPooledUDPConn_ReadMessage(t *testing.T) {
	expectedAddr, _ := net.ResolveUDPAddr("udp", "10.10.10.10:53")
	expectedLength := 1232

	msg := new(dns.Msg).SetQuestion("test.com.", 1)
	expectedBytes, _ := msg.Pack()

	writer := test.MockPacketConn{
		ReadFromFunc: func(bytes []byte) (int, net.Addr, error) {
			copy(bytes, expectedBytes)
			return len(expectedBytes), expectedAddr, nil
		},
	}

	conn := newPooledUDPConn(uint16(expectedLength), false, writer)

	receivedMsg, addr, err := conn.readNextPacket()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !reflect.DeepEqual(receivedMsg, expectedBytes) {
		t.Errorf("Expected a different message")
	}

	if addr.String() != expectedAddr.String() {
		t.Errorf("Expected addr %v, got %v", expectedAddr, addr)
	}
}

func TestPooledUDPConn_ReadMessage_OutOfOrder(t *testing.T) {
	t.Skipf("This test is flaky.")

	tests := []struct {
		name string
		ip   net.IP
	}{
		{
			name: "ReadMessageOutOfOrder_IPv6",
			ip:   net.ParseIP("::1"),
		},
		{
			name: "ReadMessageOutOfOrder_IPv4",
			ip:   net.ParseIP("127.0.0.1"),
		},
	}

	testPooledUDPConn := func(pool *Pool) {
		destinationPort1 := uint16(53146)
		destinationPort2 := uint16(53147)

		msg1 := new(dns.Msg).SetQuestion("test.com.", 1)
		msg2 := new(dns.Msg).SetQuestion("test.org.", 1)

		openMessages := new(sync.WaitGroup)
		openMessages.Add(2)

		var firstReceivedResponse *dns.Msg
		var secondReceivedResponse *dns.Msg
		var receivedErr error
		onReceive := func(connId uint64, msg *dns.Msg, addr string, err error) {
			if err != nil {
				receivedErr = err
			}
			if firstReceivedResponse == nil {
				firstReceivedResponse = msg
			} else {
				secondReceivedResponse = msg
			}

			openMessages.Done()
		}

		conn, _ := pool.GetOrCreate(onReceive)

		go test.ServeUDPResponse(t, destinationPort1, func(question *dns.Msg, _ *net.UDPAddr) *dns.Msg {
			time.Sleep(100 * time.Millisecond)
			answer := new(dns.Msg)
			answer.Id = question.Id
			answer.Answer = append(answer.Answer, &dns.A{
				A: net.ParseIP("1.1.1.1"),
				Hdr: dns.RR_Header{
					Name: "test.com.",
				}})
			return answer
		})
		go test.ServeUDPResponse(t, destinationPort2, func(question *dns.Msg, _ *net.UDPAddr) *dns.Msg {
			time.Sleep(50 * time.Millisecond)
			answer := new(dns.Msg)
			answer.Id = question.Id
			answer.Answer = append(answer.Answer, &dns.A{
				A: net.ParseIP("0.0.0.0"),
				Hdr: dns.RR_Header{
					Name: "test.org.",
				}})
			return answer
		})

		addr := test.MockAddr{
			Value: pool.localIP.String(),
			V6:    strings.Contains(pool.localIP.String(), ":"),
		}
		if err := conn.WriteMessageTo(msg1, addr, destinationPort1, time.Second); err != nil {
			t.Error(err)
			return
		}
		if err := conn.WriteMessageTo(msg2, addr, destinationPort2, time.Second); err != nil {
			t.Error(err)
			return
		}

		openMessages.Wait()

		// Assert
		if receivedErr != nil {
			t.Errorf("Expected no error, got %v", receivedErr)
		}
		if firstReceivedResponse.Id != msg2.Id {
			t.Errorf("Expected msg2 to be received first.")
		}
		if firstReceivedResponse.Answer[0].Header().Name != "test.org." {
			t.Errorf("Expected msg2 to contain 'test.org.'")
		}
		if secondReceivedResponse.Id != msg1.Id {
			t.Errorf("Expected msg1 to be received second.")
		}
		if secondReceivedResponse.Answer[0].Header().Name != "test.com." {
			t.Errorf("Expected msg1 to contain 'test.com.'")
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPool(tt.ip, 512, 1)
			testPooledUDPConn(p)
		})
	}
}
