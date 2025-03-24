package qmin

import (
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"strconv"
)

type Qmin struct {
	// trustedZones is a list of domains that are trusted.
	// Works like trustAllTLDs, but only for the specified domains.
	trustedZones map[model.DomainName]any

	// trustAllTLDs controls whether queries for the top level domain are send to all nameservers.
	// If true, the resolver will NOT send queries to all TLD nameservers.
	// It will trust that the all servers respond correctly and consistently and thus only send the query to a single nameserver.
	trustAllTLDs bool

	// trustedNameserverCount is the number of servers that will be queried when a zone is deemed "trusted"
	trustedNameserverCount int

	Modules ModuleCollection

	messageAnalyzer MessageAnalyzer
}

// MessageAnalyzer encapsulates logic to analyze DNS messages.
// It can be used as an extension point to inject or remove domain names into the QMIN resolver,
// although modules will be the better choice for most use cases.
// But the main reason for its existence is, that it greatly increases unit testability.
type MessageAnalyzer interface {
	GetReferrals(msg *dns.Msg, qtype uint16) []Referral
	GetCNAMES(msg *dns.Msg) []cname
	IsOnlyReferralFor(msg *dns.Msg, name model.DomainName) bool
	IsOnlyReferral(msg *dns.Msg) bool
}

type carryOverArgsQmin struct {
	zone        *model.Zone
	doNotFollow bool
}

func (c carryOverArgsQmin) String() string {
	return fmt.Sprintf("zone=%v", c.zone.Name)
}

func New() Qmin {
	return Qmin{
		messageAnalyzer:        QminMessageAnalyzer{},
		trustedNameserverCount: 1,
	}
}

func (s Qmin) TrustZones(names []model.DomainName) Qmin {
	s.trustedZones = make(map[model.DomainName]any, len(names))
	for _, name := range names {
		s.trustedZones[name] = nil
	}
	return s
}

// TrustTLDs controls whether queries for the top level domain are send to all nameservers.
// If true, the resolver will NOT send queries to all TLD nameservers.
// It will trust that the all servers respond correctly and consistently and thus only send the query to a single nameserver.
func (s Qmin) TrustTLDs(shouldTrust bool) Qmin {
	s.trustAllTLDs = shouldTrust
	return s
}

func (s Qmin) TrustedNameserverCount(count int) Qmin {
	if count < 1 {
		panic("TrustedNameserverCount must be at least 1")
	}
	s.trustedNameserverCount = count
	return s
}

func (s Qmin) AddModule(modules ...Module) Qmin {
	s.Modules = append(s.Modules, modules...)
	return s
}

func (s Qmin) OnInit(job *resolver.ResolutionJob) {
	s.Modules.OnZoneCreated(job, job.Root)

	if s.isTrusted(job.Root.Name) {
		job.Root.FixNameServer(string(job.OriginalNames[0]), s.trustedNameserverCount)
	}

	job.EnqueueRequestForFutureNameServersAndIps(job.Root, model.Ask(".", client.TypeNS), carryOverArgsQmin{
		zone: job.Root,
	}, resolver.EnqueueOpts{})
}

func (s Qmin) OnStartResolveName(job *resolver.ResolutionJob, sname model.DomainName) {

	// Post the first request(s) to start the resolving process.
	zone, closestEncloser := job.GetClosestEncloser(sname)
	log := job.GetLog()

	if closestEncloser.Equal(sname) {
		s.Modules.OnFullNameResolved(job, sname, zone)
		return // We already resolved that name
	}

	log.Debug().Msgf("Start resolving name %v from %v", sname, closestEncloser)
	child := sname.GetAncestor(common.MinInt(closestEncloser.GetLabelCount()+1, sname.GetLabelCount()))

	job.EnqueueRequestForFutureNameServersAndIps(zone, model.Ask(child, client.TypeNS),
		carryOverArgsQmin{
			zone: zone,
		}, resolver.EnqueueOpts{})

	// Make sure we capture the parent NSset if the name is at a zone cut.
	if zone.Name == child && zone.Parent != nil {
		job.EnqueueRequestForFutureNameServersAndIps(zone.Parent, model.Ask(child, client.TypeNS),
			carryOverArgsQmin{
				zone: zone.Parent,
			}, resolver.EnqueueOpts{})
	}
}

// OnResponse is the heart of the resolution algorithm.
// Given a response, it tries to enqueue the next queries or terminates.
func (s Qmin) OnResponse(job *resolver.ResolutionJob, msgEx model.MessageExchange, ns *model.NameServer, args any) {
	dnsMsg := msgEx.Message
	q := msgEx.OriginalQuestion

	// Enrich the logger with contextual information.
	log := enrichLog(job.GetLog(), q.Name, ns, msgEx)

	isFullName := job.ContainsName(q.Name)
	s.Modules.OnMessageReceived(job, ns, msgEx)

	// These are the args that are passed on from previous invocations of OnResponse
	cargs, isCargs := args.(carryOverArgsQmin)
	if !isCargs {
		log.Error().Msgf("Got unexpected args: %v", args)
		return
	}

	/*
	 * Case 1: 	FullName + A/AAAA
	 * What:  	We've resolved the A/AAAA record of a full name
	 * Action: 	check whether we found a new nameserver IP.
	 */
	if isFullName && (q.Type == client.TypeA || q.Type == client.TypeAAAA) && dnsMsg != nil {
		job.AddIPsToNameServer(&msgEx)
	}

	if cargs.doNotFollow {
		return
	}

	/*
	 * Case 2:  FullName + not a referral
	 * What:  	We have asked a Nameserver and it did not respond with only a referral, indicating that it could be authoritative.
	 * Action:  We trigger OnFullNameResolved and OnOriginalNameResolved as necessary.
	 * Why:		We don't want to miss any servers, even if they misbehave by not setting the AA bit.
	 *          Therefore treat every response that is not clearly a zone cut as a potential authoritative answer.
	 */
	if isFullName && q.Type == dns.TypeNS && (!s.messageAnalyzer.IsOnlyReferralFor(msgEx.Message, q.Name) || q.Name.Equal(cargs.zone.Name)) {
		s.Modules.OnFullNameResolved(job, q.Name, cargs.zone)
	}

	/*
	 * Case 3:  CNAME response
	 * What:  	The name server responded with a CNAME.
	 * Action:  Resolve the CNAME.
	 */
	if cnames := s.messageAnalyzer.GetCNAMES(dnsMsg); len(cnames) > 0 {
		for _, cname := range cnames {
			job.ResolveCName(cname.origin, cname.target)
		}
	}

	/*
	 * Case 4:  Referral or "self authoritative" answer
	 * What:  	The name server included nameservers in the authority or answer section
	 * Action:  Continue the referral with all nameservers in the response.
	 */
	referrals := s.messageAnalyzer.GetReferrals(dnsMsg, q.Type)
	referredToZones := s.updateZoneModel(job, q.Name, referrals, cargs.zone, log)
	s.followReferrals(job, referrals, referredToZones, q, cargs)

	/*
	 * The part below advances the resolution process - we can ignore all other types of queries.
	 */
	if q.Type != client.TypeNS {
		return
	}

	/*
	 * Case 5:  Non-referral answer for non-full name
	 * What:  	The name server responded without a referral for the name we queried. It's not necessarily a full name.
	 * Action:  Continue by asking for the next label.
	 * Why: 	We don't want to miss any queries. Unless the server clearly indicates,
	 *          that it is not authoritative for the zone, we continue asking for the next label.
	 */
	if (dnsMsg == nil || (dnsMsg.Rcode != client.RcodeNotZone && dnsMsg.Rcode != client.RcodeNotAuth)) && !s.messageAnalyzer.IsOnlyReferral(dnsMsg) ||
		cargs.zone.HasNameServer(ns) { // Don't let a server that is listed as authoritative for a zone turn us away
		for _, name := range job.GetNamesBelow(q.Name) {
			nextQName := q.Name

			if nextQName.Equal(name) {
				continue // If the name is fully expanded, we got an actual NXDomain
			}

			nextQName = name.GetAncestor(q.Name.GetLabelCount() + 1)
			nextCargs := cargs

			// We need to do this, because followReferrals might have created a new zone if the answer was an "authoritative delegation"
			// I.e. a name server IP, that serves both child and parent but has different hostnames in the NS entries.
			nextCargs.zone = job.Root.GetClosestEnclosingZone(nextQName)
			job.EnqueueRequestForFutureNameServersAndIps(nextCargs.zone, model.Ask(nextQName, client.TypeNS), nextCargs, resolver.EnqueueOpts{})
		}
	}
}

func (s Qmin) updateZoneModel(job *resolver.ResolutionJob,
	qName model.DomainName,
	referrals []Referral,
	zone *model.Zone,
	log zerolog.Logger) map[*model.Zone]any {

	createdZones := make(map[*model.Zone]any, 1)
	referredToZones := make(map[*model.Zone]any, 1)
	newNameServers := make(map[*model.NameServer]any)

	for _, referral := range referrals {

		if !qName.IsSubDomainOf(referral.ZoneName) { // Bogus referral
			onBogusReferral(job, referral, zone)
			continue
		}

		nextZone, loaded, err := zone.CreateOrGetSubzone(referral.ZoneName)
		if err != nil { // Upward referral
			log.Debug().Msgf("Failed to create or get subzone %v from parent zone %v", referral.ZoneName, zone.Name)
			continue
		}

		if !loaded {
			createdZones[nextZone] = nil
		}
		referredToZones[nextZone] = nil

		ns, loaded := job.CreateOrGetNameServer(referral.NameServer)
		if !loaded {
			newNameServers[ns] = nil
		}

		nextZone.AppendNameServer(ns)

		// TODO - what if a CNAME exists for this NS?
		// e.g. ns1.example.com. CNAME ns2.example.com.
		// and we find glue for ns2.example.com - should we add it to ns1.example.com?
		ns.AddIPs(referral.Glue...)
	}

	// For all trusted zones, pick a single name server that we plan to query.
	for zone := range createdZones {
		if s.isTrusted(zone.Name) {
			zone.FixNameServer(string(job.OriginalNames[0]), s.trustedNameserverCount)
		}
	}

	// resolve all the name server names that we have never seen before
	for ns := range newNameServers {
		job.ResolveName(ns.Name)
	}

	for zone := range createdZones {
		s.Modules.OnZoneCreated(job, zone)
	}

	return referredToZones
}

var typesToAskOnBogus = []uint16{client.TypeSOA, client.TypeNS, client.TypeA, client.TypeAAAA, client.TypeTXT, client.TypeDNSKEY, client.TypeDS, client.TypeMX}

func onBogusReferral(job *resolver.ResolutionJob, referral Referral, zone *model.Zone) {
	// Make sure we resolve the zone name directly - so we can later compare the real NS with the NSes in the bogus referral
	job.ResolveName(referral.ZoneName)

	// Resolve the names of the bogus NSes
	ns, loaded := job.CreateOrGetNameServer(referral.NameServer)
	if !loaded {
		job.ResolveName(ns.Name)
	}

	// Since every question is asked at most once, we want to give the resolver the chance to ask the questions here
	// in the right zone context first. Because the NSes in the bogus referral might very well be authoritative for the zone.
	// In that case, we want a query with "doNotFollow = false" and the right zone context.
	// So we enqueue this at the very end.
	job.OnFinished(func() {
		cargs := carryOverArgsQmin{
			doNotFollow: true, // The zone is bogus - we can't continue from here
			zone:        zone,
		}
		// Enqueue a limited set of questions
		for _, rrtype := range typesToAskOnBogus {
			job.EnqueueRequestNowAndForFutureIPs(ns, model.Ask(referral.ZoneName, rrtype), cargs, resolver.EnqueueOpts{})

			// We do not add the glue IPs to the nameserver, since they are likely to be bogus as well - we ask directly
			for _, ip := range referral.Glue {
				job.EnqueueRequestIP(ns, ip, model.Ask(referral.ZoneName, rrtype), cargs, resolver.EnqueueOpts{})
			}
		}
	})

}

func (s Qmin) followReferrals(job *resolver.ResolutionJob,
	referrals []Referral,
	referredToZones map[*model.Zone]any,
	q model.Question,
	cargs carryOverArgsQmin) {

	zone := cargs.zone

	// If required glue is missing ask the referring server for the IPs.
	// This is useful in cases where the referring server does not correctly attach glue to NS queries (but would attach to A queries)
	// or where the server may answer to this A/AAAA query directly (due to misconfiguration).
	for _, referral := range referrals {
		if q.Type != client.TypeNS && referral.IsGlueMissing() && !zone.HasNameServerWithName(referral.NameServer) {
			job.EnqueueRequestForFutureNameServersAndIps(zone, model.Ask(referral.NameServer, client.TypeA), cargs, resolver.EnqueueOpts{})
			job.EnqueueRequestForFutureNameServersAndIps(zone, model.Ask(referral.NameServer, client.TypeAAAA), cargs, resolver.EnqueueOpts{})
		}
	}

	// Now we enqueue the NS queries that advance the resolution
	for nextZone := range referredToZones {
		nextCargs := cargs
		nextCargs.zone = nextZone

		// These requests makes sure, we always request the authoritative NS record set for the zone
		job.EnqueueRequestForFutureNameServersAndIps(nextZone, model.Ask(q.Name, client.TypeNS), nextCargs, resolver.EnqueueOpts{})

		// These requests are actually advancing the resolution
		for nextQName := range getNextQNames(job, q.Name) {
			job.EnqueueRequestForFutureNameServersAndIps(nextZone, model.Ask(nextQName, client.TypeNS), nextCargs, resolver.EnqueueOpts{})
		}
	}
}

func getNextQNames(job *resolver.ResolutionJob, qName model.DomainName) map[model.DomainName]any {
	// Generate the next set of QNames to ask
	var nextQNames = make(map[model.DomainName]any)
	nextQNames[qName] = nil
	for _, fullName := range job.GetNamesBelow(qName) {
		nextQName := qName
		if !nextQName.Equal(fullName) {
			nextQName = fullName.GetAncestor(qName.GetLabelCount() + 1)
		}
		nextQNames[nextQName] = nil
	}
	return nextQNames
}

func enrichLog(log zerolog.Logger, originalQName model.DomainName, ns *model.NameServer, msgExchange model.MessageExchange) zerolog.Logger {
	logCtx := log.With().
		Str("fqdn", string(originalQName)).
		Str("ip", msgExchange.NameServerIP.String()).
		Str("nsName", string(ns.Name)).
		Str("corrId", strconv.FormatUint(msgExchange.Metadata.CorrelationId, 10))

	if log.GetLevel() <= zerolog.InfoLevel {
		logCtx.Str("qName", string(msgExchange.OriginalQuestion.Name))
		logCtx.Uint16("qType", msgExchange.OriginalQuestion.Type)
		logCtx.Uint16("qClass", msgExchange.OriginalQuestion.Class)
	}

	if log.GetLevel() <= zerolog.DebugLevel {
		logCtx.Interface("msg", msgExchange)
	}

	return logCtx.Logger()
}

func (s Qmin) isTrusted(zoneName model.DomainName) bool {
	// If we trust TLDs, and the zone is a TLD, pick a server to query
	if s.trustAllTLDs && zoneName.IsTopLevelDomain() {
		return true
	}

	// If we trust the domain in question, pick a server to query.
	if _, ok := s.trustedZones[zoneName]; ok {
		return true
	}

	// We don't trust the zone,
	return false
}
