package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/spf13/cobra"
	"math"
	"math/rand"
	"net/netip"
	"time"
)

type messageContainer struct {
	model.MessageExchange
	Domains []resolver.TaggedDomainName
	NSNames []model.DomainName
	File    string
}

var ExtractMessages = &cobra.Command{
	Use:   "extractMessages",
	Short: "Extracts and filter messages from a given input file.",
	Long:  "Extracts and filter messages from a given input file.",
	Args: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		if format != "json" && format != "protobuf" {
			return fmt.Errorf("format must be either 'json' or 'protobuf'")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		msgFilters := make([]FilterPredicate[model.MessageExchange], 0)
		resultFilters := make([]FilterPredicate[resolver.Result], 0)

		in := Must(cmd.Flags().GetString("in"))
		out := Must(cmd.Flags().GetString("out"))
		format, _ := cmd.Flags().GetString("format")
		sampleRate, _ := cmd.Flags().GetFloat32("samplerate")
		zip := Must(cmd.Flags().GetString("zip"))
		originalAndWWWOnly, _ := cmd.Flags().GetBool("original-domain-and-www")

		zipAlgo, compression, err := serialization.ParseZip(zip)
		if err != nil {
			panic(err)
		}

		if cmd.Flag("domain").Changed {
			domains := Must(cmd.Flags().GetStringSlice("domain"))
			resultFilters = append(resultFilters, DomainFilter(domains))
		}

		if cmd.Flag("nsIp").Changed {
			ips := Must(cmd.Flags().GetStringSlice("nsIp"))
			msgFilters = append(msgFilters, IpFilter(ips))
		}

		if cmd.Flag("final").Changed {
			final, _ := cmd.Flags().GetBool("final")
			msgFilters = append(msgFilters, FinalFilter(final))
		}

		if cmd.Flag("tcp").Changed {
			tcp, _ := cmd.Flags().GetBool("tcp")
			msgFilters = append(msgFilters, TcpFilter(tcp))
		}

		if cmd.Flag("tc").Changed {
			tc, _ := cmd.Flags().GetBool("tc")
			msgFilters = append(msgFilters, TruncatedFilter(tc))
		}

		if cmd.Flag("aa").Changed {
			aa, _ := cmd.Flags().GetBool("aa")
			msgFilters = append(msgFilters, AuthoritativeFilter(aa))
		}

		if cmd.Flag("fromCache").Changed {
			cached, _ := cmd.Flags().GetBool("fromCache")
			msgFilters = append(msgFilters, CacheFilter(cached))
		}

		if cmd.Flag("rateLimiting").Changed {
			rlSeconds, _ := cmd.Flags().GetInt("rateLimiting")
			msgFilters = append(msgFilters, RateLimitingFilter(time.Second*time.Duration(rlSeconds)))
		}

		from := time.UnixMilli(0)
		to := time.UnixMilli(math.MaxInt64)
		if cmd.Flag("from").Changed {
			fromStr, _ := cmd.Flags().GetString("from")
			from = Must(time.Parse(time.RFC3339, fromStr))
			msgFilters = append(msgFilters, FromFilter(from))
			resultFilters = append(resultFilters, ResultFromFilter(from))
		}
		if cmd.Flag("to").Changed {
			toStr, _ := cmd.Flags().GetString("to")
			to = Must(time.Parse(time.RFC3339, toStr))
			msgFilters = append(msgFilters, ToFilter(to))
			resultFilters = append(resultFilters, ResultToFilter(to))
		}

		if cmd.Flag("rcode").Changed {
			rcodes := Must(cmd.Flags().GetStringSlice("rcode"))
			msgFilters = append(msgFilters, RCodeFilter(rcodes))
		}

		if cmd.Flag("errorCode").Changed {
			errcodes := Must(cmd.Flags().GetStringSlice("errorCode"))
			msgFilters = append(msgFilters, ErrorCodeFilter(errcodes))
		}

		if cmd.Flag("correlationId").Changed {
			ids := Must(cmd.Flags().GetUintSlice("correlationId"))
			msgFilters = append(msgFilters, CorrelationIDFilter(ids))
		}

		if cmd.Flag("qname").Changed {
			ids := Must(cmd.Flags().GetStringSlice("qname"))
			msgFilters = append(msgFilters, QNameFilter(ids))
		}

		if cmd.Flag("qtype").Changed {
			qtypes := Must(cmd.Flags().GetUintSlice("qtype"))
			msgFilters = append(msgFilters, QtypeFilter(qtypes))
		}

		if cmd.Flag("qclass").Changed {
			qtypes := Must(cmd.Flags().GetUintSlice("qclass"))
			msgFilters = append(msgFilters, QclassFilter(qtypes))
		}

		if cmd.Flag("rtype").Changed {
			rtypes := Must(cmd.Flags().GetUintSlice("rtype"))
			msgFilters = append(msgFilters, RtypeFilter(rtypes))
		}

		outWriter, closeFunc, err := getZipFileWriter(out, zipAlgo, compression)
		if err != nil {
			panic(err)
		}
		defer closeFunc()

		c := make(chan resolver.Result, 200)
		reader := getFilteredReaderZip(in, format, false, nil, 5*time.Minute, resultFilters...)
		go func() {
			if err := reader.ReadTo(c); err != nil {
				panic(fmt.Errorf("%v %w", out, err))
			}
		}()

		for p := range c {
			domainDict := make(map[model.DomainName]any)
			for _, domain := range p.Domains {
				domainDict[domain.Name] = nil
			}

			nsIPDict := make(map[netip.Addr][]model.DomainName)
			for _, ns := range p.Zone.GetNameServersRecursive() {
				for _, ip := range ns.IPAddresses.Items() {
					nsIPDict[ip] = append(nsIPDict[ip], ns.Name)
				}
			}

		msgLoop:
			for iter := p.Msgs.Iterate(); iter.HasNext(); {
				msg := *iter.Next()
				for _, predicate := range msgFilters {
					if !predicate(msg) {
						continue msgLoop
					}
				}

				if originalAndWWWOnly {
					_, isOrig := domainDict[msg.OriginalQuestion.Name]
					_, isWWWOrig := domainDict[msg.OriginalQuestion.Name.WithWWW()]
					if !isOrig && !isWWWOrig {
						continue
					}
				}

				//nolint:gosec // we don't need cryptographically secure random numbers here
				if rand.Float32() > sampleRate {
					continue
				}

				c := messageContainer{
					Domains:         p.Domains,
					MessageExchange: msg,
					File:            in,
					NSNames:         nsIPDict[msg.NameServerIP],
				}

				bytes, err := json.Marshal(c)
				if err != nil {
					panic(err)
				}
				if _, err = outWriter.Write(bytes); err != nil {
					panic(err)
				}
				if _, err = outWriter.Write([]byte("\n")); err != nil {
					panic(err)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(ExtractMessages)

	ExtractMessages.Flags().String("in", "", "")
	ExtractMessages.Flags().String("out", "messages.json", "")
	ExtractMessages.Flags().String("format", "protobuf", "")
	ExtractMessages.Flags().Float32("samplerate", 1, "")
	ExtractMessages.Flags().String("zip", "", "")

	ExtractMessages.Flags().Bool("original-domain-and-www", false, "")

	ExtractMessages.Flags().Bool("final", false, "")
	ExtractMessages.Flags().Bool("tc", false, "")
	ExtractMessages.Flags().Bool("aa", false, "")
	ExtractMessages.Flags().Bool("tcp", false, "")
	ExtractMessages.Flags().Bool("fromCache", false, "")
	ExtractMessages.Flags().Bool("timeout", false, "")
	ExtractMessages.Flags().Int("rateLimiting", 60, "Extracts rate limited messages where either a ratelimiting timeout occurred or dequeueTime-enqueueTime > x")

	ExtractMessages.Flags().String("from", "", "")
	ExtractMessages.Flags().String("to", "", "")
	ExtractMessages.Flags().UintSlice("correlationId", []uint{}, "CorrelationId(s) to extract.")
	ExtractMessages.Flags().StringSlice("rcode", []string{}, "Rcode(s) to extract.")
	ExtractMessages.Flags().StringSlice("nsIp", []string{}, "")
	ExtractMessages.Flags().StringSlice("errorCode", []string{}, "")
	ExtractMessages.Flags().UintSlice("qtype", []uint{}, "")
	ExtractMessages.Flags().UintSlice("qclass", []uint{}, "")
	ExtractMessages.Flags().UintSlice("rtype", []uint{}, "")
	ExtractMessages.Flags().StringSlice("qname", []string{}, "")
	ExtractMessages.Flags().StringSlice("domain", []string{}, "")
}
