package qmin

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/miekg/dns"
	"net/netip"
)

// Referral
// Our use differs from the definition in rfc8499
// Our 'Referral' can originate from the answer section (in which case the referring server is authoritative for the subzone to)
// Still some servers include glue with those responses (which we might want to use).
// And for the QNAME minimization algorithm, these types of responses are treated the same.
type Referral struct {
	// ZoneName is the name of the referred-to zone
	ZoneName model.DomainName

	// NameServer is the name of the referred-to nameserver
	NameServer model.DomainName

	Glue []netip.Addr

	// True, if the 'Referral' originated from the answer section of the response (see Referral for explanation)
	FromAnswer bool
}

type cname struct {
	origin model.DomainName
	target model.DomainName

	// The name server can optionally provide records together with the cname to shorten the resolution path.
	// Such records are stored here.
	records []dns.RR
}

var _ MessageAnalyzer = new(QminMessageAnalyzer)

type QminMessageAnalyzer struct{}

// IsGlueMissing returns true if the referral should contain required glue
func (r Referral) IsGlueMissing() bool {
	return !r.FromAnswer && r.NameServer.IsSubDomainOf(r.ZoneName) && len(r.Glue) == 0
}

// IsOnlyReferralFor returns true if the msg contains ONLY a referral for the given name.
func (QminMessageAnalyzer) IsOnlyReferralFor(msg *dns.Msg, name model.DomainName) bool {
	// From rfc8499
	// A response that has only a referral contains an empty answer
	// section.  It contains the NS RRset for the referred-to zone in the
	// Authority section.  It may contain RRs that provide addresses in
	// the additional section.  The AA bit is clear.

	if msg == nil {
		return false
	}
	if msg.Authoritative {
		return false
	}
	if msg.Truncated {
		return false
	}
	if len(msg.Answer) > 0 {
		return false
	}

	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeNS && name.EqualString(rr.Header().Name) {
			return true
		}
	}

	return false
}

// IsOnlyReferral returns true if the msg contains ONLY a referral.
func (QminMessageAnalyzer) IsOnlyReferral(msg *dns.Msg) bool {
	// From rfc8499
	// A response that has only a referral contains an empty answer
	// section.  It contains the NS RRset for the referred-to zone in the
	// Authority section.  It may contain RRs that provide addresses in
	// the additional section.  The AA bit is clear.

	if msg == nil {
		return false
	}
	if msg.Authoritative {
		return false
	}
	if msg.Truncated {
		return false
	}
	if len(msg.Answer) > 0 {
		return false
	}

	// At least on NS record in the auth section
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeNS {
			return true
		}
	}

	return false
}

func (QminMessageAnalyzer) GetReferrals(msg *dns.Msg, qtype uint16) []Referral {
	if msg == nil {
		return nil
	}

	expectedSize := len(msg.Ns)
	if qtype == dns.TypeNS {
		expectedSize += len(msg.Answer)
	}

	response := make([]Referral, 0, expectedSize)
	glue := indexGlue(msg, expectedSize)

	for _, rr := range msg.Ns {
		nsRecord, isNS := rr.(*dns.NS)
		if !isNS {
			continue
		}

		if r, err := newReferral(nsRecord, glue, false); err == nil {
			response = append(response, r)
		}
	}

	// Optimization - only parse the answer section if we have asked for NS records
	if qtype != dns.TypeNS {
		return response
	}

	for _, rr := range msg.Answer {
		nsRecord, isNS := rr.(*dns.NS)
		if !isNS {
			continue
		}

		if r, err := newReferral(nsRecord, glue, true); err == nil {
			response = append(response, r)
		}
	}

	return response
}

func newReferral(nsRecord *dns.NS, glueIdx map[model.DomainName][]netip.Addr, fromAnswer bool) (Referral, error) {
	nsName, err := model.NewDomainName(nsRecord.Ns)
	if err != nil {
		return Referral{}, err
	}
	zoneName, err := model.NewDomainName(nsRecord.Header().Name)
	if err != nil {
		return Referral{}, err
	}

	return Referral{
		ZoneName:   zoneName,
		NameServer: nsName,
		Glue:       glueIdx[nsName],
		FromAnswer: fromAnswer,
	}, nil
}

func (QminMessageAnalyzer) GetCNAMES(msg *dns.Msg) []cname {
	if msg == nil {
		return nil
	}

	var response []cname
	for _, cnameRecord := range msg.Answer {
		cnameRec, isCname := cnameRecord.(*dns.CNAME)
		if !isCname {
			continue
		}

		name, err := model.NewDomainName(cnameRec.Header().Name)
		if err != nil {
			continue
		}

		val, err := model.NewDomainName(cnameRec.Target)
		if err != nil {
			continue
		}

		response = append(response, cname{
			origin: name,
			target: val,
			records: common.Filter(msg.Answer, func(rr dns.RR) bool {
				return val.EqualString(rr.Header().Name)
			}),
		})
	}

	return response
}

func indexGlue(msg *dns.Msg, cap int) map[model.DomainName][]netip.Addr {
	result := make(map[model.DomainName][]netip.Addr, cap)
	if msg == nil {
		return result
	}

	for _, rec := range msg.Extra {
		if ipRec, ok := rec.(*dns.A); ok {
			name, err := model.NewDomainName(ipRec.Hdr.Name)
			if err != nil {
				continue
			}

			ips, _ := result[name]

			if ip, success := netip.AddrFromSlice(ipRec.A); success {
				result[name] = append(ips, ip)
			}
			continue
		}

		if ipRec, ok := rec.(*dns.AAAA); ok {
			name, err := model.NewDomainName(ipRec.Hdr.Name)
			if err != nil {
				continue
			}

			ips, _ := result[name]

			if ip, success := netip.AddrFromSlice(ipRec.AAAA); success {
				result[name] = append(ips, ip)
			}

			continue
		}
	}

	return result
}
