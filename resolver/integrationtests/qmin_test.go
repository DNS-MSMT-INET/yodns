package integrationtests

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/builder"
	resolver2 "github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/cache"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	qmin2 "github.com/DNS-MSMT-INET/yodns/resolver/qmin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var ipQuestionTemplates = []qmin2.QuestionTemplate{{
	NameTemplate: qmin2.PlaceholderName,
	Type:         client.TypeA,
	Class:        dns.ClassINET,
}, {
	NameTemplate: qmin2.PlaceholderName,
	Type:         client.TypeAAAA,
	Class:        dns.ClassINET,
}}

func Test_NSIsCNAME(t *testing.T) {
	// No test domain to verify that, we tweak the responses that we receive...
	domainName := model.MustNewDomainName("example.com.")
	authNS := model.MustNewDomainName("a.iana-servers.net.")
	authNS2 := model.MustNewDomainName("b.iana-servers.net.")
	cnameNS := model.MustNewDomainName("cname.iana-servers.net.")

	m := qmin2.Module{
		// Removes the glue from responses from one of the parent NSes
		OnMessageReceived: func(job *resolver2.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {

			// Replace the name server name in the referral with a CNAME
			if msgEx.OriginalQuestion == model.Ask(domainName, client.TypeNS) {
				msgEx.Message.Extra = []dns.RR{}
				msgEx.Message.Ns = []dns.RR{
					&dns.NS{
						Hdr: dns.RR_Header{
							Name:   string(domainName),
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    100,
						},
						Ns: string(cnameNS),
					},
				}
			}

			// Inject the CNAME response
			if msgEx.OriginalQuestion.Name.Equal(cnameNS) {
				msgEx.Message.Extra = []dns.RR{}
				msgEx.Message.Answer = []dns.RR{
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name:   string(cnameNS),
							Rrtype: dns.TypeCNAME,
							Class:  dns.ClassINET,
							Ttl:    100,
						},
						Target: string(authNS),
					},
				}
			}

		},
	}

	strategy := qmin2.New().
		AddModule(m).
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(domainName, strategy, false)

	primaryCname := findNameServer(result, cnameNS)
	primary := findNameServer(result, authNS)
	secondary := findNameServer(result, authNS2)

	if primaryCname == nil {
		t.Errorf("Expected %v to be added to the list of name servers", cnameNS)
		return
	}
	if primaryCname.IPAddresses.Len() != primary.IPAddresses.Len() {
		t.Errorf("Expected IP addressess of CNAME and primary to be the same.")
	}
	for _, ip := range primaryCname.IPAddresses.Items() {
		if !primary.IPAddresses.Contains(ip) {
			t.Errorf("Expected IP addressess of CNAME and primary to be the same.")
		}
	}

	// Not a super good test but kinda useful.
	pMsgs := result.Msgs.GetMessagesByNameServer(primaryCname).ToList()
	sMsgs := result.Msgs.GetMessagesByNameServer(secondary).ToList()
	if len(pMsgs) != len(sMsgs) {
		t.Errorf("Expected the same messages to be send to all servers.")
	}
}

func Test_CNAMEOnApex(t *testing.T) {
	// No test domain to verify that, we tweak the responses that we receive...
	subdomainName := model.MustNewDomainName("subdomain.example.com.")
	domainName := model.MustNewDomainName("example.com.")
	cname := model.MustNewDomainName("example.org.")

	m := qmin2.Module{
		// Removes the glue from responses from one of the parent NSes
		OnMessageReceived: func(job *resolver2.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {

			// Replace original response in authoritative messages with a CNAME response
			if msgEx.Message.Authoritative && msgEx.OriginalQuestion.Name.Equal(domainName) {
				msgEx.Message.Extra = []dns.RR{}
				msgEx.Message.Answer = []dns.RR{
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name:   string(domainName),
							Rrtype: dns.TypeCNAME,
							Class:  dns.ClassINET,
							Ttl:    100,
						},
						Target: string(cname),
					},
				}
			}
		},
	}

	strategy := qmin2.New().
		AddModule(m).
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(subdomainName, strategy, false)

	if _, exists := findMessage(result, model.Ask(subdomainName, client.TypeA)); !exists {
		t.Errorf("Expected subdomain to be found, even if apex CNAME is 'in between'.")
	}
	if _, exists := findMessage(result, model.Ask(cname, client.TypeNS)); !exists {
		t.Errorf("Expected CNAME on apex to be followed.")
	}
}

func Test_CNAME(t *testing.T) {
	subDomain := model.MustNewDomainName("subdomain.example.com.")
	subsubDomain := model.MustNewDomainName("www.subdomain.example.com.")
	cname := model.MustNewDomainName("example.org.")

	m := qmin2.Module{
		// Removes the glue from responses from one of the parent NSes
		OnMessageReceived: func(job *resolver2.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {

			if msgEx.Message.Authoritative && msgEx.OriginalQuestion.Name.Equal(subDomain) {
				msgEx.Message.Extra = []dns.RR{}
				msgEx.Message.Answer = []dns.RR{
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name:   string(subDomain),
							Rrtype: dns.TypeCNAME,
							Class:  dns.ClassINET,
							Ttl:    100,
						},
						Target: string(cname),
					},
				}
			}
		},
	}

	strategy := qmin2.New().
		AddModule(m).
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(subsubDomain, strategy, false)

	if _, exists := findMessage(result, model.Ask(subsubDomain, client.TypeA)); !exists {
		t.Errorf("Expected subsubdomain to be found, even if CNAME is 'in between'.")
	}
	if _, exists := findMessage(result, model.Ask(cname, client.TypeA)); !exists {
		t.Errorf("Expected CNAME to be followed.")
	}
}

func Test_AskOriginalDomainForWWWIfCNAME(t *testing.T) {
	domainName := model.MustNewDomainName("wsfat3.blogspot.com.")
	cname := model.MustNewDomainName("blogspot.l.googleusercontent.com.")
	authNSName := model.MustNewDomainName("ns1.google.com.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates,
			[]qmin2.QuestionTemplate{
				{
					NameTemplate: "www." + qmin2.PlaceholderName,
					Type:         client.TypeA,
					Class:        dns.ClassINET,
				},
			}))

	result := resolveDomainName(domainName, strategy, false)

	// Assert that the original domain is asked for www
	q := model.Ask("www."+cname, client.TypeA)
	if _, ok := findMessage(result, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSName)
	}

	// Assert that CNAME has been asked for www.
	q = model.Ask("www."+domainName, client.TypeA)
	if _, ok := findMessage(result, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSName)
	}
}

func Test_AsksLateDiscoveredIPs(t *testing.T) {
	// No test domain to verify that, so we just delete one specific IP from all referrals
	domainName := model.MustNewDomainName("google.com.")
	authNS := model.MustNewDomainName("ns1.google.com.")
	authNSIP := netip.MustParseAddr("216.239.32.10")

	m := qmin2.Module{
		// Removes the glue from responses from one of the parent NSes
		OnMessageReceived: func(job *resolver2.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {
			idx := 0
			for i, rr := range msgEx.Message.Extra {
				if aRec, ok := rr.(*dns.A); ok {
					a, _ := netip.AddrFromSlice(aRec.A)
					if a == authNSIP {
						idx = i
					}
				}
			}

			msgEx.Message.Extra = slices.Delete(msgEx.Message.Extra, idx, idx+1)
		},
	}

	strategy := qmin2.New().
		AddModule(m).
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(domainName, strategy, false)

	q := model.Ask(authNS, client.TypeA)
	if _, ok := findMessageFromServer(result, authNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNS)
	}

	q = model.Ask(authNS, client.TypeAAAA)
	if _, ok := findMessageWithIP(result, authNSIP, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSIP)
	}
	q = model.Ask(authNS, client.TypeA)
	if _, ok := findMessageWithIP(result, authNSIP, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSIP)
	}
	q = model.Ask(domainName, client.TypeAAAA)
	if _, ok := findMessageWithIP(result, authNSIP, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSIP)
	}
	q = model.Ask(authNS, client.TypeA)
	if _, ok := findMessageWithIP(result, authNSIP, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSIP)
	}
	q = model.Ask(authNS, client.TypeNS)
	if _, ok := findMessageWithIP(result, authNSIP, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSIP)
	}
}

func Test_AsksIPsIfGlueIsMissing(t *testing.T) {
	// No test domain to verify that we just delete the glue from a referral
	// This tests asserts that if required glue is missing, we ask the referring server for the NS IP directly

	domainName := model.MustNewDomainName("google.com.")
	authNS := model.MustNewDomainName("ns1.google.com.")
	parentNS := model.MustNewDomainName("a.gtld-servers.net.")

	m := qmin2.Module{
		// Removes the glue from responses from one of the parent NSes
		OnMessageReceived: func(job *resolver2.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {
			if ns.Name.Equal(parentNS) &&
				msgEx.OriginalQuestion.Type == client.TypeNS &&
				msgEx.OriginalQuestion.Name.Equal(domainName) {
				msgEx.Message.Extra = []dns.RR{}
			}
		},
	}

	strategy := qmin2.New().
		AddModule(m).
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(domainName, strategy, false)

	q := model.Ask(authNS, client.TypeA)
	if _, ok := findMessageFromServer(result, parentNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, parentNS)
	}

	q = model.Ask(authNS, client.TypeAAAA)
	if _, ok := findMessageFromServer(result, parentNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, parentNS)
	}

}

func Test_AsksLateDiscoveredNS(t *testing.T) {
	// The zone org.afilias-nst.org. has an authoritative in the child NS set which is not in the parent set - namely b2.org.afilias-nst.org
	// This test makes sure, that all relevant questions are asked to it, even though it is discovered "later"
	domainName := model.MustNewDomainName("example.org.")
	lateNSName := model.MustNewDomainName("b2.org.afilias-nst.org")
	earlyNSNAme := model.MustNewDomainName("a0.org.afilias-nst.info")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(domainName, strategy, false)

	// It should be asked for the NS records
	q := model.Ask("org.afilias-nst.org.", client.TypeNS)
	if _, ok := findMessageFromServer(result, lateNSName, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, lateNSName)
	}

	// For the IPs and records of other names in the zone
	q = model.Ask(earlyNSNAme, client.TypeNS)
	if _, ok := findMessageFromServer(result, lateNSName, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, lateNSName)
	}
	q = model.Ask(earlyNSNAme, client.TypeA)
	if _, ok := findMessageFromServer(result, lateNSName, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, lateNSName)
	}

	// And the "early" NSes should be asked for the "late NS
	q = model.Ask(lateNSName, client.TypeNS)
	if _, ok := findMessageFromServer(result, earlyNSNAme, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, lateNSName)
	}
	q = model.Ask(lateNSName, client.TypeA)
	if _, ok := findMessageFromServer(result, earlyNSNAme, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, lateNSName)
	}

}

func Test_TCPFallbackIfResponseTruncated(t *testing.T) {
	domainName := model.MustNewDomainName("co.uk.")
	truncatingNS := model.MustNewDomainName("dns1.nic.uk")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(domainName, strategy, true) // Dnssec for larger response size

	ns := findNameServer(result, truncatingNS)
	q := model.Ask("uk.", client.TypeNS)
	hasTruncatedMsg := false
	hasTCPMsg := false
	for iter := result.Msgs.GetMessagesByNameServer(ns); iter.HasNext(); {
		msg := iter.Next()
		if msg.OriginalQuestion == q && !msg.Metadata.IsFinal && msg.Message.Truncated {
			hasTruncatedMsg = true
		}

		if msg.OriginalQuestion == q && msg.Metadata.IsFinal && !msg.Message.Truncated && msg.Metadata.TCP {
			hasTCPMsg = true
		}
	}

	if !hasTruncatedMsg {
		t.Errorf("Expected first answer to %v to be truncated.", q)
	}
	if !hasTCPMsg {
		t.Errorf("Expected retry of%v over tcp.", q)
	}
}

func Test_TrustSingleZone(t *testing.T) {
	domainName := model.MustNewDomainName("a.icann-servers.net.")
	trustedZone := model.MustNewDomainName("com.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil)).
		TrustZones([]model.DomainName{trustedZone})

	result := resolveDomainName(domainName, strategy, false)

	var slds []*model.Zone
	for _, zone := range result.Zone.Flatten() {
		if zone.Name.GetLabelCount() == 3 { // SLD (note does not work for co.uk etc., but good enough for this test)
			slds = append(slds, zone)
		}
	}

	for _, sld := range slds {
		tld := sld.Parent

		count := 0
		for _, parentNS := range tld.NameServers {
			if _, ok := findMessageFromServer(result, parentNS.Name, model.Ask(sld.Name, client.TypeNS)); ok {
				count++
			}
		}

		// Assert that questions to TLD zones have only been asked once
		if sld.Name.IsSubDomainOf(trustedZone) && count != 1 {
			t.Errorf("Expected %v to be asked to one parent nameserver, got %v", model.Ask(sld.Name, client.TypeNS), count)
		}
		if !sld.Name.IsSubDomainOf(trustedZone) && count == 1 {
			t.Errorf("Expected %v to be asked to all parent nameserver because only %v is trusted, got %v", model.Ask(sld.Name, client.TypeNS), trustedZone, count)
		}
	}
}

func Test_TrustTLD(t *testing.T) {
	domainName := model.MustNewDomainName("a.icann-servers.net.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil)).
		TrustTLDs(true)

	result := resolveDomainName(domainName, strategy, false)

	var slds []*model.Zone
	for _, zone := range result.Zone.Flatten() {
		if zone.Name.GetLabelCount() == 3 { // SLD (note does not work for co.uk etc., but good enough for this test)
			slds = append(slds, zone)
		}
	}

	for _, sld := range slds {
		tld := sld.Parent

		count := 0
		for _, parentNS := range tld.NameServers {
			if _, ok := findMessageFromServer(result, parentNS.Name, model.Ask(sld.Name, client.TypeNS)); ok {
				count++
			}
		}

		// Assert that questions to TLD zones have only been asked once
		if count != 1 {
			t.Errorf("Expected %v to be asked to one parent nameserver, got %v", model.Ask(sld.Name, client.TypeNS), count)
		}
	}
}

func Test_AsksForParentAndChildNSSet(t *testing.T) {
	domainName := model.MustNewDomainName("example.org.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil))

	result := resolveDomainName(domainName, strategy, false)

	for _, zone := range result.Zone.Flatten() {
		q := model.Ask(zone.Name, client.TypeNS)

		// Assert that each parent nameserver has been asked for NS records
		if zone.Parent != nil {
			for _, ns := range zone.Parent.NameServers {
				if _, ok := findMessageFromServer(result, ns.Name, q); !ok {
					t.Errorf("Expected %v to be asked to parent NS %v", q, ns.Name)
				}
			}
		}

		// Assert that each child nameserver has been asked for NS records
		// Unless the same NS is responsible for parent and child.
		for _, ns := range zone.NameServers {
			if _, ok := findMessageFromServer(result, ns.Name, q); !ok {
				t.Errorf("Expected %v to be asked to authoritative NS %v", q, ns.Name)
			}
		}
	}
}

func Test_AsksForBindVersion(t *testing.T) {
	domainName := model.MustNewDomainName("example.com.")
	nsWithBind := model.MustNewDomainName("a.gtld-servers.net.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates,
			[]qmin2.QuestionTemplate{
				{
					NameTemplate: "version.bind.",
					Type:         client.TypeTXT,
					Class:        dns.ClassCHAOS,
				},
			}))

	result := resolveDomainName(domainName, strategy, false)

	q := model.Ask("version.bind.", client.TypeTXT)
	q.Class = client.ClassCHAOS

	// Assert that version.bind. has been sent to each IP
	// (Not necessarily each nameserver name)
	var nsIPs = make(map[netip.Addr]bool)
	for _, ns := range result.Zone.GetNameServersRecursive() {
		for _, ip := range ns.IPAddresses.Items() {
			nsIPs[ip] = false
		}
	}
	for iter := result.Msgs.Iterate(); iter.HasNext(); {
		if msg := iter.Next(); msg.OriginalQuestion == q {
			nsIPs[msg.NameServerIP] = true
		}
	}
	for ip := range nsIPs {
		if !nsIPs[ip] {
			t.Errorf("Expected %v to be asked to %v", q, ip)
		}
	}

	if msg, ok := findMessageFromServer(result, nsWithBind, q); ok {
		if len(msg.Message.Answer) != 1 {
			t.Errorf("Expected an answer to version.bind. from %v", nsWithBind)
		}
	}

}

func Test_AsksForDNSSEC(t *testing.T) {
	domainName := model.MustNewDomainName("example.com.")
	rootNS := model.MustNewDomainName("k.root-servers.net.")
	tldNameServer := model.MustNewDomainName("a.gtld-servers.net.")
	authNS := model.MustNewDomainName("a.iana-servers.net.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates,
			[]qmin2.QuestionTemplate{
				{
					NameTemplate: qmin2.PlaceholderZone,
					Type:         client.TypeDS,
					Class:        dns.ClassINET,
				},
				{
					NameTemplate: qmin2.PlaceholderZone,
					Type:         client.TypeDNSKEY,
					Class:        dns.ClassINET,
				},
				{
					NameTemplate: qmin2.PlaceholderZone,
					Type:         client.TypeDS,
					Class:        dns.ClassINET,
					AskParent:    true,
				},
				{
					NameTemplate: qmin2.PlaceholderZone,
					Type:         client.TypeDNSKEY,
					Class:        dns.ClassINET,
					AskParent:    true,
				},
			}))

	result := resolveDomainName(domainName, strategy, true)

	q := model.Ask(".", client.TypeDNSKEY)
	if _, ok := findMessageFromServer(result, rootNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, rootNS)
	}
	q = model.Ask("com.", client.TypeDNSKEY)
	if _, ok := findMessageFromServer(result, tldNameServer, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, tldNameServer)
	}
	q = model.Ask("example.com.", client.TypeDNSKEY)
	if _, ok := findMessageFromServer(result, authNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNS)
	}

	q = model.Ask("com.", client.TypeDS)
	if _, ok := findMessageFromServer(result, rootNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, rootNS)
	}
	q = model.Ask("example.com.", client.TypeDS)
	if _, ok := findMessageFromServer(result, tldNameServer, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, tldNameServer)
	}

	// Note that the records below, if they exist, are misconfigurations.
	// We nevertheless query them.

	q = model.Ask("com.", client.TypeDNSKEY)
	if _, ok := findMessageFromServer(result, rootNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, rootNS)
	}
	q = model.Ask("example.com.", client.TypeDNSKEY)
	if _, ok := findMessageFromServer(result, tldNameServer, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, tldNameServer)
	}

	q = model.Ask(".", client.TypeDS)
	if _, ok := findMessageFromServer(result, rootNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, rootNS)
	}
	q = model.Ask("com.", client.TypeDS)
	if _, ok := findMessageFromServer(result, tldNameServer, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, tldNameServer)
	}
	q = model.Ask("example.com.", client.TypeDS)
	if _, ok := findMessageFromServer(result, authNS, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNS)
	}
}

func Test_AskZoneForDMarc(t *testing.T) {
	domainName := model.MustNewDomainName("icann.org.")
	authNSName := model.MustNewDomainName("a.icann-servers.net.")

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates,
			[]qmin2.QuestionTemplate{
				{
					NameTemplate: "_dmarc." + qmin2.PlaceholderName,
					Type:         client.TypeTXT,
					Class:        dns.ClassINET,
				},
			}))

	result := resolveDomainName(domainName, strategy, false)

	// Assert that the original domain is asked for www
	q := model.Ask("_dmarc."+domainName, client.TypeTXT)
	if _, ok := findMessage(result, q); !ok {
		t.Errorf("Expected %v to be asked to %v", q, authNSName)
	}

	// Make a list of all zones
	zoneNames := make(map[model.DomainName]bool)
	for _, zone := range result.Zone.Flatten() {
		zoneNames[zone.Name] = false
	}

	if len(zoneNames) < 1 {
		t.Errorf("There has been some resolution error. Expecting more zones.")
	}

	// Search for dmarc queries and assert that ONLY zones are queried for dmarc records
	for iter := result.Msgs.Iterate(); iter.HasNext(); {
		msg := iter.Next()
		if strings.HasPrefix(string(msg.OriginalQuestion.Name), "_dmarc") {
			zone := model.MustNewDomainName(strings.TrimPrefix(string(msg.OriginalQuestion.Name), "_dmarc."))

			if _, isZoneName := zoneNames[zone]; !isZoneName {
				t.Errorf("Expected only zones to be queried for dmarc. '%v' was queried but is not a zone.", zone)
			}
			zoneNames[zone] = true
		}

	}

	// Assert that ALL zones are queried for dmarc
	for zone := range zoneNames {
		if !zoneNames[zone] {
			t.Errorf("Expected zones %v to be queried for dmarc.", zone)
		}
	}
}

func findMessage(result resolver2.Result, question model.Question) (*model.MessageExchange, bool) {
	for iter := result.Msgs.Iterate(); iter.HasNext(); {
		if msg := iter.Next(); msg.OriginalQuestion == question {
			return msg, true
		}
	}
	return nil, false
}

func findMessageFromServer(result resolver2.Result, nameServerName model.DomainName, question model.Question) (*model.MessageExchange, bool) {
	ns := findNameServer(result, nameServerName)
	if ns == nil {
		return nil, false
	}

	for iter := result.Msgs.GetMessagesByNameServer(ns); iter.HasNext(); {
		msg := iter.Next()
		if msg.OriginalQuestion == question && msg.Metadata.IsFinal {
			return msg, true
		}
	}

	return nil, false
}

func findMessageWithIP(result resolver2.Result, ip netip.Addr, question model.Question) (*model.MessageExchange, bool) {
	for iter := result.Msgs.GetMessagesByIP(ip); iter.HasNext(); {
		msg := iter.Next()
		if msg.OriginalQuestion == question && msg.Metadata.IsFinal && msg.NameServerIP == ip {
			return msg, true
		}
	}

	return nil, false
}

func findNameServer(result resolver2.Result, nameServerName model.DomainName) *model.NameServer {
	for _, ns := range result.Zone.GetNameServersRecursive() {
		if ns.Name.Equal(nameServerName) {
			return ns
		}
	}
	return nil
}

func resolveDomainName(domainName model.DomainName, strategy resolver2.Strategy, dnssec bool) resolver2.Result {
	ctx := common.Background()
	dnsCache := cache.NewDNSCache(math.MaxInt64)
	go dnsCache.Start()

	infraCache := cache.NewInfraCache(5*time.Minute,
		math.MaxUint64,
		cache.ConstantBackoff{Value: 5 * time.Second},
		zerolog.Logger{})
	go infraCache.Start()

	var localIPV4 net.IP
	if conn, err := net.Dial("udp", "9.9.9.9:53"); err == nil {
		localIPV4 = conn.LocalAddr().(*net.UDPAddr).IP
		_ = conn.Close()
	} else {
		panic(err)
	}

	var localIPV6 net.IP
	if conn, err := net.Dial("udp", "[2001:4860:4860::9999]:53"); err == nil {
		localIPV6 = conn.LocalAddr().(*net.UDPAddr).IP
		_ = conn.Close()
	} else {
		panic(err)
	}

	// Initialize and decorate the DNS client with the necessary functionality
	dnsClient := new(builder.Builder).
		WithRateLimiting(10, 10, time.Minute).
		WithLocalIPs(localIPV4, localIPV6).
		WithTCPPoolSize(100).
		WithTCPEphemeralConns(100).
		WithUDPPoolSize(10).
		Build(ctx)

	// Use maxInflight as number of request workers.
	// Each request worker can wait for one request, so using n workers we can only have so many open requests.
	worker := resolver2.NewWorker(dnsClient, dnsCache, infraCache, 2)

	go worker.Dequeue(ctx)

	r := resolver2.New(worker, strategy, rootServers...).GatherDNSSEC(dnssec)

	return r.Resolve(ctx, resolver2.TaggedDomainName{Name: domainName})
}
