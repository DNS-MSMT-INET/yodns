package cmd

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type FilterPredicate[T any] func(msg T) bool

func RCodeFilter(rCodes []string) FilterPredicate[model.MessageExchange] {
	rcodeMap := make(map[int]any)
	for _, str := range rCodes {
		if str != "" {
			rcodeMap[Must(strconv.Atoi(strings.TrimSpace(str)))] = nil
		}
	}

	return func(msg model.MessageExchange) bool {
		if len(rCodes) == 0 {
			return false
		}

		rcode := -1
		if msg.Message != nil {
			rcode = msg.Message.Rcode
		}

		_, ok := rcodeMap[rcode]
		return ok
	}
}

func FromFilter(from time.Time) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Metadata.EnqueueTime.After(from)
	}
}

func ToFilter(to time.Time) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Metadata.DequeueTime.Before(to)
	}
}

func ResultFromFilter(from time.Time) FilterPredicate[resolver.Result] {
	return func(r resolver.Result) bool {
		return r.StartTime.Add(r.Duration).After(from)
	}
}

func ResultToFilter(to time.Time) FilterPredicate[resolver.Result] {
	return func(r resolver.Result) bool {
		return r.StartTime.Before(to)
	}
}

func TruncatedFilter(tc bool) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Message != nil &&
			msg.Message.Truncated == tc
	}
}

func AuthoritativeFilter(aa bool) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Message != nil &&
			msg.Message.Authoritative == aa
	}
}

func IpFilter(ips []string) FilterPredicate[model.MessageExchange] {
	ipMap := make(map[netip.Addr]any)
	for _, ip := range ips {
		ipMap[netip.MustParseAddr(ip)] = nil
	}

	return func(msg model.MessageExchange) bool {
		_, ok := ipMap[msg.NameServerIP]
		return ok
	}
}

func CorrelationIDFilter(ids []uint) FilterPredicate[model.MessageExchange] {
	idMap := make(map[uint]any)
	for _, id := range ids {
		idMap[id] = nil
	}

	return func(msg model.MessageExchange) bool {
		_, ok := idMap[uint(msg.Metadata.CorrelationId)]
		return ok
	}
}

func QNameFilter(names []string) FilterPredicate[model.MessageExchange] {
	nameMap := make(map[model.DomainName]any)
	for _, name := range names {
		nameMap[model.MustNewDomainName(name)] = nil
	}

	return func(msg model.MessageExchange) bool {
		_, ok := nameMap[msg.OriginalQuestion.Name]
		return ok
	}
}

func QtypeFilter(types []uint) FilterPredicate[model.MessageExchange] {
	typeMap := make(map[uint16]any)
	for _, t := range types {
		typeMap[uint16(t)] = nil
	}

	return func(msg model.MessageExchange) bool {
		_, ok := typeMap[msg.OriginalQuestion.Type]
		return ok
	}
}

func QclassFilter(classes []uint) FilterPredicate[model.MessageExchange] {
	classMap := make(map[uint16]any)
	for _, t := range classes {
		classMap[uint16(t)] = nil
	}

	return func(msg model.MessageExchange) bool {
		_, ok := classMap[msg.OriginalQuestion.Class]
		return ok
	}
}

func RtypeFilter(types []uint) FilterPredicate[model.MessageExchange] {
	typeMap := make(map[uint16]any)
	for _, t := range types {
		typeMap[uint16(t)] = nil
	}

	return func(msg model.MessageExchange) bool {
		if msg.Message == nil {
			return false
		}

		for _, rr := range msg.Message.Answer {
			if _, ok := typeMap[rr.Header().Rrtype]; ok {
				return true
			}
		}
		return false
	}
}

func CacheFilter(fromCache bool) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Metadata.FromCache == fromCache
	}
}

func FinalFilter(isFinal bool) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Metadata.IsFinal == isFinal
	}
}

func TcpFilter(isTCP bool) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		return msg.Metadata.TCP == isTCP
	}
}

func RateLimitingFilter(duration time.Duration) FilterPredicate[model.MessageExchange] {
	return func(msg model.MessageExchange) bool {
		rateLimitTimeout := msg.Error != nil && (msg.Error.Code == client.ErrorCodeRateLimitTimeout ||
			msg.Error.Code == client.ErrorCodeImpossibleRateLimit ||
			msg.Error.Code == client.ErrorCodePredictedRateLimitTimeout)
		return rateLimitTimeout || msg.Metadata.DequeueTime.Sub(msg.Metadata.EnqueueTime) > duration
	}
}

func DomainFilter(domains []string) FilterPredicate[resolver.Result] {
	dnMap := make(map[model.DomainName]any)
	for _, domain := range domains {
		dnMap[model.MustNewDomainName(domain)] = nil
	}

	return func(r resolver.Result) bool {
		for _, domain := range r.Domains {
			_, ok := dnMap[domain.Name]
			if ok {
				return true
			}
		}
		return false
	}
}

func ErrorCodeFilter(codes []string) FilterPredicate[model.MessageExchange] {
	codeMap := make(map[string]any)
	for _, code := range codes {
		codeMap[strings.TrimSpace(strings.ToLower(code))] = nil
	}

	return func(msg model.MessageExchange) bool {
		if msg.Error == nil {
			return false
		}

		_, ok := codeMap[strings.ToLower(string(msg.Error.Code))]
		return ok
	}
}
