package internal

import (
	"context"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"github.com/godruoyi/go-snowflake"
	"reflect"
	"testing"
	"time"
)

func TestConnectionReusingClient_Enqueue(t *testing.T) {
	tests := []struct {
		name         string
		useTCP       bool
		wantUDPCalls int32
		wantTCPCalls int32
	}{
		{
			name:         "Enqueue_UDP",
			useTCP:       false,
			wantUDPCalls: 1,
			wantTCPCalls: 0,
		},
		{
			name:         "Enqueue_TCP",
			useTCP:       true,
			wantUDPCalls: 0,
			wantTCPCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			udpClient := &test.MockClient{
				ReceivedCalls: 0,
			}
			tcpClient := &test.MockClient{
				ReceivedCalls: 0,
			}

			reusingClient := NewReusingClient(udpClient, tcpClient)
			sendOpts := client.SendOpts{
				UseTCP: tt.useTCP,
			}
			reusingClient.Enqueue(snowflake.ID(), client.Question{}, new(test.MockAddr), sendOpts)

			if udpClient.ReceivedCalls != tt.wantUDPCalls {
				t.Errorf("Expected %v calls to UDP, got %v", udpClient.ReceivedCalls, tt.wantUDPCalls)
			}
			if tcpClient.ReceivedCalls != tt.wantTCPCalls {
				t.Errorf("Expected %v calls to TCP, got %v", tcpClient.ReceivedCalls, tt.wantTCPCalls)
			}
		})
	}
}

func TestConnectionReusingClient_FanIn(t *testing.T) {
	udpClient := &test.MockClient{
		ReceivedCalls: 0,
		RespChan:      make(chan client.Response, 1),
	}
	tcpClient := &test.MockClient{
		ReceivedCalls: 0,
		RespChan:      make(chan client.Response, 1),
	}

	udpResp := client.Response{
		CorrelationId: snowflake.ID(),
	}
	tcpResp := client.Response{
		CorrelationId: snowflake.ID(),
	}

	udpClient.RespChan <- udpResp
	tcpClient.RespChan <- tcpResp

	reusingClient := NewReusingClient(udpClient, tcpClient).Start(context.Background())

	gotUDP := false
	gotTCP := false

	select {
	case <-time.After(time.Second):
		t.Errorf("Receive Timeout")
	case result := <-reusingClient.ResponseChan():
		switch {
		case reflect.DeepEqual(result, udpResp):
			gotUDP = true
		case reflect.DeepEqual(result, tcpResp):
			gotTCP = true
		default:
			t.Errorf("Expected %v or %v, got %v", udpResp, tcpResp, result)
		}
	}

	select {
	case <-time.After(time.Second):
		t.Errorf("Receive Timeout")
	case result := <-reusingClient.ResponseChan():
		switch {
		case reflect.DeepEqual(result, udpResp):
			gotUDP = true
		case reflect.DeepEqual(result, tcpResp):
			gotTCP = true
		default:
			t.Errorf("Expected %v or %v, got %v", udpResp, tcpResp, result)
		}
	}

	if !gotTCP || !gotUDP {
		t.Errorf("Expected to receive both, UDP and TCP responses")
	}
}
