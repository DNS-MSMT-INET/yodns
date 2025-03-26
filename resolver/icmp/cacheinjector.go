package icmp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/rs/zerolog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io"
	"net"
	"net/netip"
	"time"
)

// dialFunc is used for creating a new connection from which ICMP packets can be read.
// overwrite in unit tests to inject mocks.
var dialFunc = newICMPListener

var ErrShortHeader = errors.New("header too short")

type Cache interface {
	MarkUnresponsive(ip netip.Addr, reason string)
}

// CacheInjector receives ICMP messages and marks name-servers as unreachable in the cache.
type CacheInjector struct {
	cache     Cache
	out       io.Writer
	log       zerolog.Logger
	localIPv6 net.IP
	localIPv4 net.IP
}

// serMessage is the format for serializing received icmp messages
type serMessage struct {
	SourceAddr string
	Timestamp  time.Time
	Body       []byte
}

type icmpParams struct {
	protocolNumber             int
	typeDestinationUnreachable icmp.Type
	parseDst                   func(body *icmp.DstUnreach) (net.IP, error)
}

var icmpIPV4 = icmpParams{
	protocolNumber:             1,
	typeDestinationUnreachable: ipv4.ICMPTypeDestinationUnreachable,
	parseDst: func(body *icmp.DstUnreach) (net.IP, error) {
		if len(body.Data) < ipv4.HeaderLen {
			return nil, ErrShortHeader
		}

		hdr, err := ipv4.ParseHeader(body.Data[0:ipv4.HeaderLen])
		if err != nil {
			return nil, err
		}

		return hdr.Dst.To4(), nil
	},
}

var icmpIPV6 = icmpParams{
	protocolNumber:             58,
	typeDestinationUnreachable: ipv6.ICMPTypeDestinationUnreachable,
	parseDst: func(body *icmp.DstUnreach) (net.IP, error) {
		if len(body.Data) < ipv6.HeaderLen {
			return nil, ErrShortHeader
		}

		hdr, err := ipv6.ParseHeader(body.Data[0:ipv6.HeaderLen])
		if err != nil {
			return nil, err
		}

		return hdr.Dst, nil
	},
}

func (ci CacheInjector) Inject(cache Cache) CacheInjector {
	ci.cache = cache
	return ci
}

func (ci CacheInjector) LogTo(logger zerolog.Logger) CacheInjector {
	ci.log = logger
	return ci
}

func (ci CacheInjector) WriteTo(out io.Writer) CacheInjector {
	ci.out = out
	return ci
}

func (ci CacheInjector) ListenV6(localIPv6 net.IP) CacheInjector {
	ci.localIPv6 = localIPv6
	return ci
}

func (ci CacheInjector) ListenV4(localIPv4 net.IP) CacheInjector {
	ci.localIPv4 = localIPv4
	return ci
}

func (ci CacheInjector) Start(ctx common.Context) error {
	var connV4 net.PacketConn
	var connV6 net.PacketConn
	var err error

	if ci.localIPv4 != nil {
		if connV4, err = dialFunc(ci.localIPv4); err != nil {
			return err
		}
	}
	if ci.localIPv6 != nil {
		if connV6, err = dialFunc(ci.localIPv6); err != nil {
			return err
		}
	}

	dropRawSocketCaps()

	msgChan := make(chan serMessage, 50)

	// Will exit if channel is closed
	ctx.Go(func() { ci.writeWorker(msgChan) })

	if connV4 != nil {
		// Will exit if connection is closed
		ctx.Go(func() { ci.readICMPWorker(icmpIPV4, connV4, msgChan) })
	}
	if connV6 != nil {
		// Will exit if connection is closed
		ctx.Go(func() { ci.readICMPWorker(icmpIPV6, connV6, msgChan) })
	}

	// Close the connections when the context is done
	ctx.OnDone(func() {
		if connV4 != nil {
			_ = connV4.Close()
		}
		if connV6 != nil {
			_ = connV6.Close()
		}
		close(msgChan)
	})

	return nil
}

func (ci CacheInjector) readICMPWorker(icmpParam icmpParams, conn net.PacketConn, outChan chan<- serMessage) {
	for {
		reply := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(reply)
		reply = reply[:n]
		if err != nil {
			ci.log.Err(err).Msgf("Error reading ICMP message from connection")
			break // e.g. connection close
		}

		msg, err := icmp.ParseMessage(icmpParam.protocolNumber, reply)
		if err != nil {
			ci.log.
				Err(err).
				Str("hex_msg", hex.EncodeToString(reply)).
				Msgf("Error parsing ICMP message")
			continue
		}

		if msg.Type == icmpParam.typeDestinationUnreachable {
			body := msg.Body.(*icmp.DstUnreach)

			dst, err := icmpParam.parseDst(body)
			if err != nil {
				ci.log.Err(err).
					Str("hex_msg", hex.EncodeToString(reply)).
					Msgf("Error parsing DST ip from ICMP message body")
				continue
			}

			ip, success := netip.AddrFromSlice(dst)
			if !success {
				ci.log.Error().Msgf("Failed to convert %v to netip.Addr", dst)
				continue
			}

			ci.cache.MarkUnresponsive(ip, "ICMP DST_UNREACHABLE")
		}

		outChan <- serMessage{
			SourceAddr: addr.String(),
			Timestamp:  time.Now(),
			Body:       reply,
		}
	}
}

func (ci CacheInjector) writeWorker(c <-chan serMessage) {
	// Until channel is closed
	for msg := range c {
		if ci.out == nil {
			continue
		}

		b, err := json.Marshal(msg)
		if err != nil {
			ci.log.Err(err).Msgf("Error serializing ICMP message.")
			continue
		}

		if n, err := ci.out.Write(b); err != nil || n != len(b) {
			ci.log.Err(err).Msgf("Error writing ICMP message to log.")
			continue
		}

		if _, err := ci.out.Write([]byte("\r\n")); err != nil {
			ci.log.Err(err).Msgf("Error writing ICMP message to log.")
			continue
		}
	}
}
