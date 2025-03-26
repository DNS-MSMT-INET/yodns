package icmp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"golang.org/x/net/icmp"
	"net"
	"net/netip"
	"testing"
	"time"
)

type cacheMock struct {
	MarkUnresponsiveFunc func(netip.Addr, string)
}

func (c cacheMock) MarkUnresponsive(ip netip.Addr, reason string) {
	c.MarkUnresponsiveFunc(ip, reason)
}

var (
	// exported hex-dump via wireshark. We probably need to do this again for linux. Maybe use the ICMP package to create a message.
	ipv4DestUnreachMessage = "0300fcee001100004500003c9fb000007c015ddf8b133927cbcdb12908004d2e0001002d6162636465666768696a6b6c6d6e6f70717273747576776162636465666768690000000000000000"
)

func Test_Message(t *testing.T) {
	t.Skipf("For manual testing")

	msgHex := "030ab7b00000000045000045" // this is a broken message we received during scanning.
	strMsg, err := hex.DecodeString(msgHex)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	msg, err := icmp.ParseMessage(1, strMsg)
	fmt.Println(msg)
}

func TestCacheInjector_IPv4DestUnreach(t *testing.T) {
	expectedAddr := "203.205.177.41" // This is the value encoded in the message
	icmpMsg, err := hex.DecodeString(ipv4DestUnreachMessage)
	if err != nil {
		t.Errorf("failed to load icmp message: %v", err)
		return
	}

	calls := 0
	dialFunc = func(localAddress net.IP) (net.PacketConn, error) {
		return MockPacketConn{
			ReadFromFunc: func(bytes []byte) (int, net.Addr, error) {
				if calls > 0 { // After the first, call, do not read another message
					time.Sleep(time.Minute)
				}
				calls++
				copy(bytes, icmpMsg)
				return len(bytes), &net.UDPAddr{
					IP:   net.ParseIP("4.3.2.1"),
					Port: 53,
				}, nil
			},
		}, nil
	}

	receivedAddr := ""
	cache := cacheMock{
		MarkUnresponsiveFunc: func(s netip.Addr, unresponsiveReason string) {
			receivedAddr = s.String()
		},
	}

	localAddr := "1.2.3.4"
	out := &bytes.Buffer{}
	err = new(CacheInjector).
		Inject(cache).
		WriteTo(out).
		ListenV4(net.ParseIP(localAddr)).
		Start(common.Background())

	if err != nil {
		t.Error(err)
		return
	}

	// Allow the go-routine to read the message and call the cache
	time.Sleep(100 * time.Millisecond)

	// Ensure cache has been called
	if receivedAddr != expectedAddr {
		t.Errorf("Expected destination %v to be marked as unreachable but got %v", expectedAddr, receivedAddr)
	}

	// Ensure output has been written
	if len(out.Bytes()) == 0 {
		t.Errorf("Expected ICMP message to be written to output")
	}
}

func TestCacheInjector_IPv6DestUnreach(t *testing.T) {
	// TODO
}

// Test is not working on (my) windows. Might be the firewall filters some ICMP packages.
func TestCacheInjector_IntegrationTest(t *testing.T) {
	t.Skip()

	// Sending to 203.205.177.41 will generate a DST_UNREACH msg
	// TODO We shouldn't use any real IP for this, maybe there is an IP in the reserved range that will also do?
	remoteAddr := "203.205.177.41"

	receivedAddr := ""
	cache := cacheMock{
		MarkUnresponsiveFunc: func(s netip.Addr, reason string) {
			receivedAddr = s.String()
		},
	}

	var localIPV4 net.IP
	conn, err := net.Dial("udp", fmt.Sprintf("%v:53", remoteAddr))
	if err != nil {
		t.Errorf("failed to resolve local IP %v", err)
		return
	}
	localIPV4 = conn.LocalAddr().(*net.UDPAddr).IP
	defer conn.Close()

	err = new(CacheInjector).
		Inject(cache).
		ListenV4(localIPV4).
		Start(common.Background())
	if err != nil {
		t.Error(err)
		return
	}

	time.Sleep(time.Second)

	// provoke a DST_UNREACHABLE message
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Error(err)
		return
	}

	time.Sleep(time.Second)

	if receivedAddr != remoteAddr {
		t.Errorf("Expected destination %v to be marked as unreachable but got %v", remoteAddr, receivedAddr)
	}
}
