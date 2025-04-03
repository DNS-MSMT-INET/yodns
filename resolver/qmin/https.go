package qmin

import (
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/miekg/dns"
)

// HTTPSModule follows and resolves aliases and target names found in HTTPS records.
// HTTPS records are automatically queried for all *full names*.
func HTTPSModule() Module {
	return Module{
		// Enqueues queries for HTTPS records for every full name encountered
		OnFullNameResolved: func(job *resolver.ResolutionJob, name model.DomainName, zone *model.Zone) {
			q := model.Question{
				Type:  dns.TypeHTTPS,
				Class: dns.ClassINET,
				Name:  name,
			}
			job.EnqueueRequestForFutureNameServersAndIps(zone, q, carryOverArgsQmin{zone: zone}, resolver.EnqueueOpts{})
		},
		// Parses responses to HTTPS queries and triggers resolution of the target names found in the HTTPS record.
		OnMessageReceived: func(job *resolver.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {
			if msgEx.OriginalQuestion.Type != dns.TypeHTTPS {
				return
			}

			for _, answer := range msgEx.Message.Answer {
				https, ok := answer.(*dns.HTTPS)
				if !ok {
					continue
				}

				if https.Target != "." && https.Target != "" && https.Target != https.Hdr.Name {
					dn, err := model.NewDomainName(https.Target)
					if err != nil {
						job.GetLog().Warn().Msgf("Failed to create domain name from HTTPS target '%s' with err '%v'", https.Target, err)
						continue
					}
					job.ResolveName(dn)
				}
			}
		},
	}
}
