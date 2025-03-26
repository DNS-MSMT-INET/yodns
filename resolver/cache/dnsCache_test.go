package cache

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/klauspost/compress/zstd"
	"github.com/miekg/dns"
	"math"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestDnsCache_CanSetAndGet(t *testing.T) {
	tests := []struct {
		name    string
		msg     model.MessageExchange
		q       model.Question
		wantHit bool
	}{
		{
			name: "SetAndGet_CacheHit",
			msg: model.MessageExchange{
				NameServerIP: netip.MustParseAddr("1.2.3.4"),
				ResponseAddr: "1.2.3.4:53",
				OriginalQuestion: model.Question{
					Name:  "test.com",
					Type:  1,
					Class: 1,
				},
				Metadata: model.Metadata{
					FromCache: true,
				},
			},
			q: model.Question{ // Same question, should work
				Name:  "test.com",
				Type:  1,
				Class: 1,
			},
			wantHit: true,
		},
		{
			name: "SetAndGet_CacheMiss",
			msg: model.MessageExchange{
				NameServerIP: netip.MustParseAddr("1.2.3.4"),
				ResponseAddr: "1.2.3.4:53",
				OriginalQuestion: model.Question{
					Name:  "test.com",
					Type:  1,
					Class: 1,
				},
				Metadata: model.Metadata{
					FromCache: true,
				},
			},
			q: model.Question{ // Different question, should not be retrieved
				Name:  "test.org",
				Type:  1,
				Class: 1,
			},
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewDNSCache(math.MaxInt64)
			cache.Set(tt.msg)

			ip := tt.msg.NameServerIP
			result, exists := cache.Get(ip, tt.q)

			if exists != tt.wantHit {
				t.Errorf("Expected exists to %v, got %v", tt.wantHit, exists)
			}

			if tt.wantHit && !reflect.DeepEqual(tt.msg, result) {
				t.Errorf("got = %v, want %v", result, tt.msg)
			}
		})
	}
}

func TestDnsCache_SetExisting_ExpectTTLUpdated(t *testing.T) {
	entry := model.MessageExchange{
		NameServerIP: netip.MustParseAddr("1.2.3.4"),
		OriginalQuestion: model.Question{
			Name:  "test.com",
			Type:  1,
			Class: 1,
		},
		Message: &dns.Msg{
			Answer: []dns.RR{
				&dns.NS{
					Ns: "a.ns.example.com.",
					Hdr: dns.RR_Header{
						Ttl: 1,
					},
				},
			},
		},
		Metadata: model.Metadata{
			FromCache: true,
		},
	}

	cache := NewDNSCache(math.MaxInt64)
	cache.Set(entry)
	time.Sleep(500 * time.Millisecond)
	cache.Set(entry)

	// Entry will be expired if it wasn't updated
	time.Sleep(800 * time.Millisecond)

	ip := entry.NameServerIP
	result, exists := cache.Get(ip, entry.OriginalQuestion)

	if !exists {
		t.Errorf("Expected exists to true")
	}
	if !reflect.DeepEqual(entry, result) {
		t.Errorf("DNSCache.Get() got = %v, want %v", result, entry)
	}
}

func TestDnsCache_CanExpire(t *testing.T) {
	entry := model.MessageExchange{
		NameServerIP: netip.MustParseAddr("1.2.3.4"),
		OriginalQuestion: model.Question{
			Name:  "test.com",
			Type:  1,
			Class: 1,
		},
		Message: &dns.Msg{
			Answer: []dns.RR{
				&dns.NS{
					Ns: "a.ns.example.com.",
					Hdr: dns.RR_Header{
						Ttl: 1,
					},
				},
			},
		},
		Metadata: model.Metadata{
			FromCache: true,
		},
	}

	cache := NewDNSCache(math.MaxInt64)
	cache.Set(entry)

	time.Sleep(1200 * time.Millisecond) // After this, the infraEntry should be expired.

	ip := entry.NameServerIP
	result, exists := cache.Get(ip, entry.OriginalQuestion)

	if exists {
		t.Errorf("Expected infraEntry to not exist anymore")
	}
	if !reflect.DeepEqual(result, model.MessageExchange{}) {
		t.Errorf("Get() got = %v, want default", result)
	}
}

func TestDnsCache_Load(t *testing.T) {
	inputFile, _ := os.Open("C:\\Users\\fsteurer.LAP-21-0158\\Documents\\dnsmonitor\\experiments\\data\\tranco\\2023-08-29-11-27_1fcd458\\cache_Aug-29-12-39-14.zst")
	reader := bufio.NewReader(inputFile)
	zReader, _ := zstd.NewReader(reader)

	newCache := NewDNSCache(math.MaxInt64)
	newCache.LoadCacheFromBinary(zReader)

	fmt.Println(newCache.innerCache.Len())
}

func TestDnsCache_CanDumpAndLoadCacheContentToBinary(t *testing.T) {
	cache := NewDNSCache(math.MaxInt64)

	msg1 := getMessage("example.com.")
	msg2 := getMessage("example.org.")

	cache.Set(msg1)
	cache.Set(msg2)

	memBuffer := new(bytes.Buffer)
	cache.DumpCacheAsBinary(time.Now().Add(time.Hour), memBuffer)

	if len(memBuffer.Bytes()) == 0 {
		t.Errorf("DNSCache.DumpCacheAsBinary() did not write any content.")
	}

	newCache := NewDNSCache(math.MaxInt64)
	newCache.LoadCacheFromBinary(memBuffer)

	assertMessageExists := func(msg model.MessageExchange) {
		ip := msg.NameServerIP
		result, exists := newCache.Get(ip, msg.OriginalQuestion)

		if !exists {
			t.Errorf("Item not present after loading cache from file")
		}

		if !reflect.DeepEqual(result, msg) {
			t.Errorf("DNSCache.Get() got = %v, want %v", result, msg)
		}
	}

	assertMessageExists(msg1)
	assertMessageExists(msg2)
}

func TestDnsCache_DumpAndLoadCacheToBinary_ExpectExpiredItemsToBeRemoved(t *testing.T) {
	msg := model.MessageExchange{
		NameServerIP: netip.MustParseAddr("1.2.3.4"),
		OriginalQuestion: model.Question{
			Name:  "domain.name.",
			Type:  1,
			Class: 2,
		},
		Message: &dns.Msg{
			Answer: []dns.RR{
				&dns.NS{
					Ns: "a.ns.example.com.",
					Hdr: dns.RR_Header{
						Ttl: 1,
					},
				},
			},
		},
		Metadata: model.Metadata{
			FromCache: true,
		},
	}

	cache := NewDNSCache(math.MaxInt64)
	cache.Set(msg)
	time.Sleep(time.Second)

	memBuffer := new(bytes.Buffer)
	cache.DumpCacheAsBinary(time.Now(), memBuffer)

	if len(memBuffer.Bytes()) > 0 {
		t.Errorf("Expected expired item to not be serialized")
	}
}

func TestDnsCache_DumpAndLoadCacheToBinary_ExpectLateItemsToBeRemoved(t *testing.T) {
	msg := model.MessageExchange{
		NameServerIP: netip.MustParseAddr("1.2.3.4"),
		OriginalQuestion: model.Question{
			Name:  "domain.name.",
			Type:  1,
			Class: 2,
		},
		Message: &dns.Msg{
			Answer: []dns.RR{
				&dns.NS{
					Ns: "a.ns.example.com.",
					Hdr: dns.RR_Header{
						Ttl: 100,
					},
				},
			},
		},
		Metadata: model.Metadata{
			FromCache: true,
		},
	}

	cache := NewDNSCache(math.MaxInt64)

	cutoffTime := time.Now()
	time.Sleep(time.Second)

	cache.Set(msg)

	memBuffer := new(bytes.Buffer)
	cache.DumpCacheAsBinary(cutoffTime, memBuffer)

	if len(memBuffer.Bytes()) > 0 {
		t.Errorf("Expected expired item to not be serialized")
	}
}

func getMessage(domainName model.DomainName) model.MessageExchange {
	return model.MessageExchange{
		NameServerIP: netip.MustParseAddr("1.2.3.4"),
		OriginalQuestion: model.Question{
			Name:  domainName,
			Type:  1,
			Class: 2,
		},
		Message: &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "a.ns.example.com.",
					Qtype:  2,
					Qclass: 1,
				},
			},
		},
		Metadata: model.Metadata{
			FromCache: true,
		},
	}
}
