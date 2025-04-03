package runner

import (
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	qmin2 "github.com/DNS-MSMT-INET/yodns/resolver/qmin"
	"math"
	"strings"
	"time"
)

type Options struct {
	// Input determines how to read the input (aka target list)
	Input InputConfig

	// Output determines how to write the output.
	Output OutputConfig

	// Retry specifies the retry behavior
	Retry RetryConfig

	// Caching specifies the cache behavior.
	Caching CachingConfig

	// MemoryLimitInGB sets the amount of RAM that can be used, before parallelism is reduced
	// in order to reduce the memory footprint temporarily and avoid an OOM exception.
	// Negative values disable this feature.
	MemoryLimitInGB int

	// ResolutionTimeoutInSeconds is the max time that the resolution of a single domain (or batch) is allowed to take
	ResolutionTimeoutInSeconds uint

	// MaxQueriesPerResolution is the max number of queries that are allowed to be sent for a single domain (or batch)
	MaxQueriesPerResolution uint

	// Connectivity
	TCP TCPConfig
	UDP UDPConfig

	// MaxQueriesPerSecondPerIP sets the rate limit for queries per second per IP.
	// If set to N, the resolver will be able to send apx. N queries to an IP per second,
	// unless the maximum number of inflight queries (MaxInflightPerIP) would be exceeded.
	MaxQueriesPerSecondPerIP int

	// MaxInflightPerIP sets the maximum number of queries that are allowed to be in-flight at the same time per IP.
	// If set to N, the resolver will never allow more than N queries inflight per unique IP.
	// It is used in addition to MaxQueriesPerSecondPerIP to avoid overloading servers that are slow to respond so
	// A good choice for this parameter depends on your latency and should be determined experimentally.
	MaxInflightPerIP int

	// RateLimitingTimeoutInSeconds sets the time that the resolver will allow queries to be delayed in the rate-limiter.
	// After this duration, a query will time out (will not be send)
	// If you chose a reasonable large value (e.g. 120s) and still see timeouts, this is most likely caused by hotspots.
	// Hotspots can occur e.g. by just scanning a specific infrastructure, or not randomizing your input.
	// In order to resolve this, either use input batching, reorder/randomize your target list or reduce the parallelism of the scan (MaxParallelism, MaxBatchParallelism).
	RateLimitingTimeoutInSeconds int

	// IPV6Only instructs the resolver to only use IPv6.
	IPV6Only bool

	// IPV4Only instructs the resolver to only use IPv4.
	IPV4Only bool

	// Level to log to. Currently 'debug', 'info', 'warn' are supported.
	Loglevel string

	// Logfile is the path to the logfile.
	Logfile string

	// Metrics contains the configuration for the metrics exporting.
	Metrics MetricsConfig

	// If set, loads the cache dump before starting the scan
	CacheDumpFile string

	// ProgressDumpFile writes a file with indexes from the target list that
	// have already been scanned. Useful for continuing crashed scans.
	// On resume, indexes that are present in the file will be skipped.
	ProgressDumpFile string

	// MaxParallelism is the maximum number of parallel resolutions.
	// This is independent of batch processing.
	// If batching is enabled, also consider setting MaxBatchParallelism to limit the number of batches.
	MaxParallelism uint

	// MaxBatchParallelism is the maximum number of parallel batches that can be resolved if batching is enabled in Input.
	// Without batching (batchSize=1), this parameter has the same effect as MaxParallelism.
	// The resolver adhere to the minimum of MaxParallelism and MaxBatchParallelism.
	// Example: If MaxParallelism=10 and MaxBatchParallelism=2, there can be at most two batches inflight, totalling 10 resolutions.
	MaxBatchParallelism uint

	// DoNotScanList contains a list to the file containing the IPs and Domainnames that should not be scanned.
	// It will be periodically reloaded every DoNotScanListReloadIntervalInSeconds seconds.
	DoNotScanList string

	// DoNotScanListReloadIntervalInSeconds is the interval in seconds in which the DoNotScanList is reloaded.
	DoNotScanListReloadIntervalInSeconds int

	// EnableICMP enables listening to ICMP messages.
	// When receiving a DST_UNREACHABLE message, the resolver will cache the server as unreachable for
	// the duration specified in CachingConfig.InfraTTLInSeconds
	EnableICMP bool

	// ICMPOutPath sets the path to a file to which all received ICMP messages are written.
	ICMPOutPath string

	// WarmUp adds a small delay when enqueueing the first between the first MaxParallelism names.
	// It reduces the load on the TLD and Root servers during ramp-up by filling the cache before going full speed.
	WarmUp bool

	// GatherDNSSEC sets the DO bit in all queries to request DNSSEC related records.
	GatherDNSSEC bool

	// QueryFor specifies which queries to ask for.
	QueryFor QueryConfig

	// RootServers contains the root server glue.
	RootServers []resolver.NameServerSeed

	// Modules contains a list of module names that will be initialized.
	Modules []string

	// MaxCNAMEDepth sets the maximum depth to which CNAMES will be followed.
	// Set to 0 to disable following CNAMES.
	MaxCNAMEDepth uint

	// TrustedZones is a list of domains that are trusted.
	// Works like TrustAllTLDs, but only for the specified domains.
	// Zones do not need to be a TLD, but can be any name.
	TrustedZones []string

	// TrustAllTLDs controls whether queries for the top level domain are send to all nameservers.
	// If true, the resolver will NOT send queries to all TLD nameservers.
	// It will trust that the all servers respond correctly and consistently and thus only send the query to a single nameserver.
	TrustAllTLDs bool

	// TrustedZoneNSCount specifies the number of nameservers that will be asked for a trusted zone during a resolution.
	// For example, if set to 1, a random nameserver will be queried (on all IP addresses)
	// Even though the idea of trusted zones is, that they are very reliable and one need not to query all nameservers,
	// a value of 2 is recommended to allow for some backup in case one name server still fails unexpectedly or
	// there are connectivity problems to that specific subnet.
	TrustedZoneNSCount int
}

type QueryConfig struct {
	// OnFullNameResolved contains queries that will be send when a full name is resolved.
	// That includes, resolved name servers, the original name, and names enqueued by other modules such as mail servers.
	OnFullNameResolved []qmin2.QuestionTemplate

	// OnZoneCreated is triggered whenever a new zone is created.
	// This is the place to ask questions that you want to ask once per zone, e.g. SOA records.
	OnZoneCreated []qmin2.QuestionTemplate
}

// MetricsConfig contains the configuration for the metrics instrumentation
// So far, metrics can be exposed via an HTTP(s) endpoint and protected
// by basic-auth. When using basic auth, make sure to also use HTTPS.
//
// In the future we could support Client-Certificate authentication or OAuth
// (The prometheus scraper had some trouble with the client cert)
type MetricsConfig struct {
	// EndpointPort is the port under which the prometheus endpoint will be exposed
	EndpointPort int

	// ServerCrtPath the path to the CER file for enabling HTTPS
	ServerCrtPath string

	// ServerKeyPath is the path to the KEY file for enabling HTTPS on the metrics endpoint
	ServerKeyPath string

	// PasswordChecksum and UserNameChecksum enable basic auth.
	// PasswordChecksum contains the hex-encoded sha256 checksum of the password as provided by
	// a := sha256.Sum256([]byte("the password"))
	// fmt.Println(hex.EncodeToString(a[:]))
	PasswordChecksum string

	// PasswordChecksum and UserNameChecksum enable basic auth.
	// PasswordChecksum contains the hex-encoded sha256 checksum of the username as provided by
	// a := sha256.Sum256([]byte("the username"))
	// fmt.Println(hex.EncodeToString(a[:]))
	UserNameChecksum string

	// If FilePath is set, metrics will be reported periodically to the given text file
	FilePath string
}

// UDPConfig contains the config for UDP connectivity
type UDPConfig struct {
	// Disable turns off UDP. Scanning will be done using TCP only.
	Disable bool

	// PoolSize is the size of the UDP socket pool
	PoolSize uint16

	// TimeoutInMs is the timeout for read and write operations on the connection
	TimeoutInMs uint

	// BufferSize sets the desired buffer size for UDP packets.
	// It will be communicated via EDNS0 to the server.
	BufferSize uint16
}

// TCPConfig contains the config for TCP connectivity
type TCPConfig struct {
	// Disable turns off TCP. Scanning will be done using UDP only.
	Disable bool

	// PoolSize is the size of the TCP connection pool
	PoolSize uint16

	// EphemeralConns is the max. number of open TCP ephemeral connections,
	// that is, connections which are used for one exchange and closed afterwards.
	// If EphemeralConns are available, the client will use them as a fallback mechanism
	// if the pool is exhausted or the pooled conns are faulty.
	EphemeralConns uint16

	// IdlePeriodInMs is the period after which a TCP connection is considered idle by the pool
	// and closing is initiated.
	IdlePeriodInMs uint

	// TimeoutInMs is the timeout for read and write operations on the connection
	TimeoutInMs uint

	// DialTimeoutInMs is the timeout for opening a TCP connection
	DialTimeoutInMs uint

	// If true, the EDNS0-TCP Keepalive option (rfc7828) is sent with a value
	// that corresponds to IdlePeriodInMs. Answers from servers are parsed for
	// keepalive-responses and the IdlePeriod of connections in the pool is adjusted
	// to respect the servers choice.
	UseKeepAlive bool
}

// InputConfig contains the settings that control the input
type InputConfig struct {
	// Format can currently be either CSV or IPRange
	Format string

	// Path to the input file
	Path string

	// CSVColumnIndex specifies the column of the csv input file that contains the domain names.
	// Only valid if Format=CSV
	CSVColumnIndex int

	// CSVSeparator specifies the separator for the CSV. Default is comma (,). Only single characters are allowed.
	// Only valid if Format=CSV
	CSVSeparator string

	// Offset specifies the number of entries that are skipped from the beginning of the input list.
	Offset uint

	// Len specifies the number of entries that are read from the list.
	// E.g. if you use a top million list as input and specify
	// Offset=1000, Len=200, you will scan the entries at index 1000-1200
	Len uint

	// BatchSize can reduce storage needs and increase resolution speed if your target list contains domains
	// that share the same second level domain. E.g. a.x.example.com, b.example.com and example.com.
	// The more labels the batch shares, the better.
	// Batching only happens if the input contains consecutive runs of domains that share the same
	// second level domain. In that case, the resolver will read at most BatchSize items and put
	// them into the same resolution. Batched entries are written into the same line of output.
	BatchSize uint

	// Path to a public suffix list. Needed for batching.
	PSLPath string
}

// OutputConfig contains the settings that control the output
type OutputConfig struct {
	// Path is the path to which the output is written
	Path string

	// OutputFileSize is the number of target domains per file.
	FileSize uint

	// Format defines the kind of outputter that is used.
	// Currently supported: 'json' and 'protobuf'
	Format string

	// Zip controls the compression method of the output files.
	// Supported format: 'algorithm' or 'algorithm:level'
	// Currently supported algorithms: 'none', 'zst', 'gzip', 'deflate'
	// Currently supported compression levels: 'fastest', 'fast', 'better'
	// Unless compatibility demands a certain format, it is recommended to use
	// 'zst' as it provides more compression and faster speed than the others.
	// When using compression levels other than 'fastest', make sure your machine
	// can write the data fast enough. Otherwise, memory will fill up and overflow.
	Zip string

	// ParallelFiles is the number of files that can be written (open) in parallel
	ParallelFiles uint32
}

// CachingConfig contain all settings related to caching
type CachingConfig struct {
	// Capacity controls the number of items that are allowed in the DNS message cache.
	// If the capacity is reached, old entries  are evicted if new ones are added
	Capacity uint64

	// InfraCapacity controls the number of items that are allowed in the infrastructure cache.
	// If the capacity is reached, old entries are evicted if new ones are added
	InfraCapacity uint64

	// InfraTTLInSeconds is the default time-to-live of items in the infrastructure cache.
	// This setting also limits the amount of time that a server can be cached as dead/unresponsive.
	// Recommended value is 300 (5 minutes)
	InfraTTLInSeconds uint

	// InfraDumpFile is a path to a file to which evicted infrastructure cache entries are written
	InfraDumpFile string
}

// RetryConfig contains the settings that control the retrying
type RetryConfig struct {
	// Max number of retries done
	MaxRetries uint

	// Backoff strategy applied.
	// Currently supported 'Exponential' or 'Constant' or 'Values'
	// If 'Values' is used, specify the sequence in BackoffValuesInMs
	Backoff string

	// BackoffValues is a fixed sequence of values that will be used for backoff.
	// Only applies if Backoff=Values
	BackoffValuesInMs []int
}

var DefaultOptions = Options{
	Input: InputConfig{
		Path:           "",
		Format:         "csv",
		CSVColumnIndex: 1,
		CSVSeparator:   ",",
		Offset:         0,
		Len:            math.MaxUint,
		BatchSize:      1,
		PSLPath:        "",
	},
	Output: OutputConfig{
		Path:          "../out",
		FileSize:      100,
		Zip:           "", // none
		Format:        "json",
		ParallelFiles: 1,
	},
	Retry: RetryConfig{
		MaxRetries: 2,
		Backoff:    "Exponential",
	},
	Caching: CachingConfig{
		Capacity:          math.MaxUint64,
		InfraCapacity:     math.MaxUint64,
		InfraTTLInSeconds: 300,
		InfraDumpFile:     "",
	},

	ResolutionTimeoutInSeconds: 3600,
	MaxQueriesPerResolution:    10_000_000,
	MemoryLimitInGB:            -1,
	Loglevel:                   "info",
	Logfile:                    "",

	// Connectivity
	MaxQueriesPerSecondPerIP:     50,
	MaxInflightPerIP:             10,
	RateLimitingTimeoutInSeconds: 60,
	IPV6Only:                     false,
	IPV4Only:                     false,
	UDP: UDPConfig{
		Disable:     false,
		TimeoutInMs: 5000,
		BufferSize:  1232, // Why 1232? => http://www.dnsflagday.net/2020/
		PoolSize:    300,
	},
	TCP: TCPConfig{
		Disable:         false,
		PoolSize:        300,
		EphemeralConns:  100,
		IdlePeriodInMs:  30000,
		TimeoutInMs:     5000,
		DialTimeoutInMs: 5000,
		UseKeepAlive:    false,
	},
	MaxParallelism:                       400,
	MaxBatchParallelism:                  150,
	DoNotScanList:                        "",
	DoNotScanListReloadIntervalInSeconds: 600,

	EnableICMP:  false,
	ICMPOutPath: "",
	WarmUp:      false,

	// DNS
	GatherDNSSEC:       true,
	MaxCNAMEDepth:      64, // https://www.mail-archive.com/dnsop@ietf.org/msg22374.html
	TrustedZoneNSCount: 2,
	RootServers: []resolver.NameServerSeed{
		{
			Name:       "a.root-servers.net.",
			IPVersion4: "198.41.0.4",
			IPVersion6: "2001:503:ba3e::2:30",
		},
		{
			Name:       "b.root-servers.net.",
			IPVersion4: "170.247.170.2",
			IPVersion6: "2801:1b8:10::b",
		},
		{
			Name:       "c.root-servers.net.",
			IPVersion4: "192.33.4.12",
			IPVersion6: "2001:500:2::c",
		},
		{
			Name:       "d.root-servers.net.",
			IPVersion4: "199.7.91.13",
			IPVersion6: "2001:500:2d::d",
		},
		{
			Name:       "e.root-servers.net.",
			IPVersion4: "192.203.230.10",
			IPVersion6: "2001:500:a8::e",
		},
		{
			Name:       "f.root-servers.net.",
			IPVersion4: "192.5.5.241",
			IPVersion6: "2001:500:2f::f",
		},
		{
			Name:       "g.root-servers.net.",
			IPVersion4: "192.112.36.4",
			IPVersion6: "2001:500:12::d0d",
		},
		{
			Name:       "h.root-servers.net.",
			IPVersion4: "198.97.190.53",
			IPVersion6: "2001:500:1::53",
		},
		{
			Name:       "i.root-servers.net.",
			IPVersion4: "192.36.148.17",
			IPVersion6: "2001:7fe::53",
		},
		{
			Name:       "j.root-servers.net.",
			IPVersion4: "192.58.128.30",
			IPVersion6: "2001:503:c27::2:30",
		},
		{
			Name:       "k.root-servers.net.",
			IPVersion4: "193.0.14.129",
			IPVersion6: "2001:7fd::1",
		},
	},
	QueryFor: QueryConfig{
		OnFullNameResolved: []qmin2.QuestionTemplate{
			{
				NameTemplate: "{name}",
				Type:         client.TypeA,
				Class:        client.ClassINET,
			},
			{
				NameTemplate: "{name}",
				Type:         client.TypeAAAA,
				Class:        client.ClassINET,
			},
		},
	},
}

func (opts Options) GetTrustedZones() []model.DomainName {
	result := make([]model.DomainName, len(opts.TrustedZones))
	var err error
	for i, v := range opts.TrustedZones {
		if result[i], err = model.NewDomainName(v); err != nil {
			panic(err)
		}

	}
	return result
}

func (opts RetryConfig) BackoffValues() []time.Duration {
	result := make([]time.Duration, len(opts.BackoffValuesInMs))
	for i, v := range opts.BackoffValuesInMs {
		result[i] = time.Millisecond * time.Duration(v)
	}
	return result
}

func (opts TCPConfig) DialTimeout() time.Duration {
	return time.Millisecond * time.Duration(opts.DialTimeoutInMs)
}

func (opts TCPConfig) IdlePeriod() time.Duration {
	return time.Millisecond * time.Duration(opts.IdlePeriodInMs)
}

func (opts TCPConfig) Timeout() time.Duration {
	return time.Millisecond * time.Duration(opts.TimeoutInMs)
}

func (opts CachingConfig) InfraTTL() time.Duration {
	return time.Second * time.Duration(opts.InfraTTLInSeconds)
}

func (opts Options) RateLimitingTimeout() time.Duration {
	return time.Second * time.Duration(opts.RateLimitingTimeoutInSeconds)
}

func (opts Options) UDPTimeout() time.Duration {
	return time.Millisecond * time.Duration(opts.UDP.TimeoutInMs)
}

func (opts Options) InitModules() (result []qmin2.Module) {
	// We always add this module
	result = append(result, qmin2.QTModule(
		opts.QueryFor.OnFullNameResolved,
		opts.QueryFor.OnZoneCreated,
	))

	for _, mod := range opts.Modules {
		switch strings.ToLower(mod) {
		case "https":
			result = append(result, qmin2.HTTPSModule())
		default:
			panic(fmt.Errorf("unkown module '%v'", mod))
		}
	}

	return
}
