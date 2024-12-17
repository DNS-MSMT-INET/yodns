package rdns

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/qmin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type RDNS struct {
	messageAnalyzer qmin.MessageAnalyzer
}

type carryOverArgsQmin struct {
	zone        *model.Zone
	doNotFollow bool
}

func (s RDNS) OnInit(job *resolver.ResolutionJob) {
	ns := job.Root.GetNameServers()[0]
	job.EnqueueRequest(
		ns,
		model.Ask(".", client.TypeNS), 
		carryOverArgsQmin{
			zone: job.Root,
		}, 
		resolver.EnqueueOpts{},
	)
}

func (s RDNS) OnStartResolveName(job *resolver.ResolutionJob, sname model.DomainName) {
	zone, closestEncloser := job.GetClosestEncloser(sname)
	child := sname.GetAncestor(common.MinInt(closestEncloser.GetLabelCount()+1, sname.GetLabelCount()))

	ns := zone.GetNameServers()[0]
	job.EnqueueRequest(
		ns,
		model.Ask(child, client.TypeNS),
		carryOverArgsQmin{
			zone: zone,
		}, // maybe put queries NSs into this for retrys?
		resolver.EnqueueOpts{},
	)

	if zone.Name == child && zone.Parent != nil {
		panic("TODO: Zone Cut")
	}
}

func (s RDNS) OnResponse (job *resolver.ResolutionJob, msgEx model.MessageExchange, ns *model.NameServer, args any) {
	dnsMsg := msgEx.Message
	q := msgEx.OriginalQuestion

	isFullName := job.ContainsName(q.Name)

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
		// Full name resolved?
		panic("TODO")
	}

	/*
	 * Case 3:  CNAME response
	 * What:  	The name server responded with a CNAME.
	 * Action:  Resolve the CNAME.
	 */
	 if cnames := s.messageAnalyzer.GetCNAMES(dnsMsg); len(cnames) > 0 {
		for _, cname := range cnames {
			_ = cname
			panic("TODO")
		}
	}

	/*
	 * Case 4:  Referral or "self authoritative" answer
	 * What:  	The name server included nameservers in the authority or answer section
	 * Action:  Continue the referral with all nameservers in the response.
	 */
	// referrals := s.messageAnalyzer.GetReferrals(dnsMsg, q.Type)
	// referredToZones := s.updateZoneModel(job, q.Name, referrals, cargs.zone, job.GetLog())
	// s.followReferrals(job, referrals, referredToZones, q, cargs)

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
			if q.Name.Equal(name) {
				continue
			}

			nextQName := name.GetAncestor(q.Name.GetLabelCount() + 1)
			nextCargs := cargs

			nextCargs.zone = job.Root.GetClosestEnclosingZone(nextQName)
			
			ns := nextCargs.zone.GetNameServers()[0]
			job.EnqueueRequest(
				ns,
				model.Ask(nextQName, client.TypeNS),
				carryOverArgsQmin{
					zone: nextCargs.zone,
				}, // maybe put queries NSs into this for retrys?
				resolver.EnqueueOpts{},
			)
		}
	}
}


func New() RDNS {
	return RDNS{
		messageAnalyzer: qmin.QminMessageAnalyzer{},
	}
}