package integrationtests

import (
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/builder"
	resolver2 "github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/cache"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	qmin2 "github.com/DNS-MSMT-INET/yodns/resolver/qmin"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var rootServers = []resolver2.NameServerSeed{
	{
		Name:       "k.root-servers.net.",
		IPVersion4: "193.0.14.129", // ip of k.root
		IPVersion6: "2001:7fd::1",  // ip of k.root
	},
}

func Test_RespectsDoNotScanList(t *testing.T) {
	aIP := netip.MustParseAddr("2001:500:8f::53")
	cIP := netip.MustParseAddr("199.43.134.53")

	input := strings.NewReader("\n2001:500:8f::53" + // a.iana-servers.net
		"\n199.43.134.0/24" + // prefix of c.iana-servers.net
		"\nb.iana-servers.net")
	if err := resolver2.DoNotScanList.FromReader(input); err != nil {
		t.Errorf("doNotScanListWrapper.FromReader() error = %v", err)
		t.FailNow()
	}

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
	worker := resolver2.NewWorker(dnsClient, dnsCache, infraCache, 1)

	go worker.Dequeue(ctx)

	strategy := qmin2.New().
		AddModule(qmin2.QTModule(ipQuestionTemplates, nil)).
		TrustTLDs(true)

	r := resolver2.New(worker, strategy, rootServers...)

	result := r.Resolve(ctx, resolver2.TaggedDomainName{Name: "example.com."})

	for iter := result.Msgs.Iterate(); iter.HasNext(); {
		msg := iter.Next()
		if msg.NameServerIP == aIP {
			if msg.Message != nil || msg.Error == nil || msg.Error.Code != model.ErrorCodeDoNotScan {
				t.Errorf("Expected %v to not be scanned.", aIP)
			}
		} else if msg.NameServerIP == cIP {
			if msg.Message != nil || msg.Error == nil || msg.Error.Code != model.ErrorCodeDoNotScan {
				t.Errorf("Expected %v to not be scanned.", cIP)
			}
		} else if msg.OriginalQuestion.Name.Equal("b.iana-servers.net.") {
			if msg.Message != nil || msg.Error == nil || msg.Error.Code != model.ErrorCodeDoNotScan {
				t.Errorf("Expected question 'b.iana-servers.net' not to be asked.")
			}
		} else {
			if msg.Error != nil && msg.Error.Code == model.ErrorCodeDoNotScan {
				t.Errorf("Expected msg %v to be send.", msg)
			}
		}
	}
}

// Test_CompareAgainstUnbound runs uses the collector to resolve A records. The results are compared with
// unbound. The collector should be able to resolve at least the same sites as unbound.
func Test_CompareAgainstUnbound(t *testing.T) {
	t.Skip()
	// docker run --name=my-unbound --publish=53:53/tcp --publish=53:53/udp --restart=unless-stopped --volume=./unbound:/opt/unbound/etc/unbound/ --detach=true mvance/unbound:latest

	//compareAgainstResolver("127.0.0.1", "../integrationtests/testdata/alexatop1k.csv", t)
	compareAgainstResolver("127.0.0.1", "../integrationtests/testdata/alexarandom1k.csv", t)
}

// Test_CompareAgainstCloudFlare runs uses the collector to resolve A records. The results are compared with
// results obtained from the public cloudflare resolver
func Test_CompareAgainstCloudFlare(t *testing.T) {
	t.Skip()

	//compareAgainstResolver("1.1.1.1", "../integrationtests/testdata/alexatop1k.csv", t)
	compareAgainstResolver("1.1.1.1", "../integrationtests/testdata/alexarandom1k.csv", t)
}

func compareAgainstResolver(resolverIP string, inputPath string, t *testing.T) {

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ctx := common.Background()
	dnsCache := cache.NewDNSCache(math.MaxInt64)
	infraCache := cache.NewInfraCache(5*time.Minute,
		math.MaxUint64,
		cache.ConstantBackoff{Value: 5 * time.Second},
		log.Logger)

	rawClient := new(dns.Client)
	rawClient.Timeout = 10 * time.Second

	// Initialize and decorate the DNS client with the necessary functionality
	dnsClient := new(builder.Builder).
		WithRateLimiting(100, 10, time.Minute).
		Build(ctx)

	// Apply the offset.
	allRecords, err := common.ReadCsvFile(inputPath)
	if err != nil {
		t.Fatalf("Can not open input file")
	}

	strategy := qmin2.New().
		AddModule(qmin2.QTModule([]qmin2.QuestionTemplate{{
			NameTemplate: qmin2.PlaceholderName,
			Type:         client.TypeA,
			Class:        dns.ClassINET,
		}}, nil))

	// Use maxInflight as number of request workers.
	// Each request worker can wait for one request, so using n workers we can only have so many open requests.
	worker := resolver2.NewWorker(dnsClient, dnsCache, infraCache, 2)

	go worker.Dequeue(ctx)

	r := resolver2.New(worker, strategy, rootServers...)

	results := sync.Map{}

	wg := new(sync.WaitGroup)
	wg.Add(len(allRecords))
	limitCh := make(chan struct{}, 10)

	for _, record := range allRecords {
		fqdn := model.MustNewDomainName(record[1])
		limitCh <- struct{}{}

		go func() {
			defer func() { <-limitCh }()
			defer wg.Done()
			result := r.Resolve(ctx, resolver2.TaggedDomainName{Name: fqdn})

			resultByCollector := ""
			//if records := result.Zone.FindRecords(fqdn, model.TypeA); len(records) > 0 {
			//	resultByCollector = records[0].Value
			//}
			fmt.Print(result)

			resultByPublicResolver, err := getFromResolver(resolverIP, rawClient, fqdn)

			results.Store(fqdn, struct {
				ResultByCollector      string
				ResultByPublicResolver string
				ErrByPublicResolver    string
			}{
				ResultByCollector:      resultByCollector,
				ResultByPublicResolver: resultByPublicResolver,
				ErrByPublicResolver:    err,
			})
		}()
	}

	wg.Wait()

	results.Range(func(k, v any) bool {
		dm := k.(model.DomainName)
		res := v.(struct {
			ResultByCollector      string
			ResultByPublicResolver string
			ErrByPublicResolver    string
		})

		if res.ResultByCollector == "" && res.ResultByPublicResolver != "" {
			t.Logf("The domain %v was resolved by the recursive r to %v but not by our r", dm, res.ResultByPublicResolver)
			log.Info().Msgf("The domain %v was resolved by Unbound to %v but not by our r", dm, res.ResultByPublicResolver)
			t.Fail()
		}
		if res.ResultByCollector != "" && res.ResultByPublicResolver == "" {
			// This is expected to happen, as we do not (and don't want to) apply any hardening
			log.Info().Msgf("The domain %v was resolved by our r to %v but not by the recursive r", dm, res.ResultByCollector)
		}
		if res.ErrByPublicResolver != "" { // Connection timeouts etc.
			log.Info().Msgf("Resolution of %v by the recursive r failed with error", res.ErrByPublicResolver)
		}
		return true
	})

}

func getFromResolver(ipAddress string, client *dns.Client, fqdn model.DomainName) (string, string) {

	var msgToSend = new(dns.Msg)
	msgToSend.SetQuestion(string(fqdn), dns.TypeA)
	msgToSend.SetEdns0(2048, false)

	r, _, err := client.Exchange(msgToSend, ipAddress+":53")

	if err != nil {
		return "", err.Error() // No result + error
	}

	for _, rr := range r.Answer {
		if fqdn.EqualString(rr.Header().Name) && rr.Header().Rrtype == dns.TypeA {
			return rr.(*dns.A).A.String(), "" // No error + result
		}
	}

	return "", "" // No error, no result
}
