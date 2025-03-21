package resolver

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/alphadose/haxmap"
	"github.com/enriquebris/goconcurrentqueue"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"math"
	"net/netip"
	"sync"
	"time"
)

type TaggedDomainName struct {
	Idx  uint
	Name model.DomainName
	Tags string
}

// Result defines the result of a resolution
type Result struct {
	Domains   []TaggedDomainName
	StartTime time.Time
	Duration  time.Duration
	Zone      *model.Zone
	Msgs      *model.MsgIdx
}

// Strategy is the resolution algorithm applied, for example QNAME minimisation or any custom logic
type Strategy interface {
	// OnInit is called exactly once when the resolution starts.
	OnInit(job *ResolutionJob)

	// OnStartResolveName is called once when the resolution of a new name starts.
	// This includes started by the strategy itself, e.g. out-of-bailiwick nameservers
	// Use it to enqueue the initial requests and start of the resolution.
	OnStartResolveName(job *ResolutionJob, sname model.DomainName)

	// OnResponse is called everytime a (final) response is received. The strategy should analyse the response
	// and enqueue follow-up requests accordingly
	OnResponse(job *ResolutionJob, response model.MessageExchange, ns *model.NameServer, args any)
}

type Worker interface {
	Enqueue(request Request)
}

type Resolver struct {
	Settings      Settings
	Strategy      Strategy
	Log           zerolog.Logger
	RootServers   []NameServerSeed
	requestWorker Worker
}

// Settings provide general settings that apply for all resolver algorithms.
type Settings struct {
	// If true, the DO bit will be set on queries.
	GatherDNSSEC bool

	// If true, IPv4 will be used to query information. By default, UseIPV4 and UseIPV6 are true, which corresponds to dual-stack resolution
	UseV4 bool

	// If true, IPv6 will be used to query information. By default, UseIPV4 and UseIPV6 are true, which corresponds to dual-stack resolution
	UseV6 bool

	// If a nameserver is multi-homed, a setting will be sent to ALL Ips of that server. Same goes for servers that have IPV4 and IPV6 addresses
	UseAllNameServerIPs bool

	// MaxCNameDepth is the max length of the CNAME chain after which the resolver will stop following CNAMES.
	// Set to 0 to not follow CNAMES at all.
	// It is recommended to set it, even if you want to follow CNAMEs indefinitely,
	// because malicious nameservers could serve a non-repeating, endless chain of CNAMEs.
	MaxCNameDepth uint

	// MaxQueries is the maximum amount of queries that will be sent for a single call to Resolve()
	MaxQueries uint
}

// ResolutionJob represents the resolution of a single domain name.
// It holds all the arguments that never change during the resolution process.
// That does explicitly NOT include the SNAME, because it can change during job execution (when hitting a CNAME)
type ResolutionJob struct {
	Root *model.Zone

	// OriginalName is the domain name that was originally requested.
	OriginalNames []model.DomainName

	// names contains the names to resolve.
	// It maps to the current depth of the cname chain
	names map[model.DomainName]uint

	// cNames contains the cNames that were encountered
	// It maps origin to targets.
	// According to specification, there should only be one target.
	// However, misconfigured names may have multiple targets.
	cNames map[model.DomainName]map[model.DomainName]any

	worker        Worker
	enqueueFunc   func(request Request)
	log           zerolog.Logger
	nameServerMap *NameServerMap

	msgs *model.MsgIdx

	strategy     Strategy
	settings     Settings
	beenThereMap *beenThereMap

	// responseQueue is the queue from which this job will receive the DNS responses
	responseQueue goconcurrentqueue.Queue

	// openRequests tracks the amount of open requests.
	// Every scheduled request increases it by 1
	// Every analyzed request decreases it by 1
	openRequests *sync.WaitGroup

	beenThereMapV2      map[mapKey]any
	onFinishedCallbacks []func()
}

type mapKey struct {
	q model.Question
	z *model.Zone
}

func New(worker Worker, strategy Strategy, rootServers ...NameServerSeed) Resolver {
	res := Resolver{
		RootServers: rootServers,
		Strategy:    strategy,
		Settings: Settings{
			GatherDNSSEC:        false,
			UseV4:               true,
			UseV6:               true,
			UseAllNameServerIPs: true,
			MaxQueries:          math.MaxUint32,
		},
		requestWorker: worker,
	}

	return res
}

func (resolver Resolver) DisableIPv4(disable bool) Resolver {
	if !resolver.Settings.UseV6 && disable {
		panic("It is not allowed to disable both IPV4 and IPV6")
	}

	resolver.Settings.UseV4 = !disable
	return resolver
}

func (resolver Resolver) DisableIPv6(disable bool) Resolver {
	if !resolver.Settings.UseV4 && disable {
		panic("It is not allowed to disable both IPV4 and IPV6")
	}

	resolver.Settings.UseV6 = !disable
	return resolver
}

func (resolver Resolver) UseAllNameServerIPs(shouldQueryAll bool) Resolver {
	resolver.Settings.UseAllNameServerIPs = shouldQueryAll
	return resolver
}

func (resolver Resolver) WithMaxQueries(maxQueries uint) Resolver {
	resolver.Settings.MaxQueries = maxQueries
	return resolver
}

func (resolver Resolver) GatherDNSSEC(shouldGatherDNSSEC bool) Resolver {
	resolver.Settings.GatherDNSSEC = shouldGatherDNSSEC
	return resolver
}

func (resolver Resolver) FollowCNAMEsToDepth(maxCNAMEDepth uint) Resolver {
	resolver.Settings.MaxCNameDepth = maxCNAMEDepth
	return resolver
}

func (resolver Resolver) LogTo(log zerolog.Logger) Resolver {
	resolver.Log = log
	return resolver
}

func (resolver Resolver) Resolve(ctx common.Context, snames ...TaggedDomainName) Result {
	if len(snames) == 0 {
		panic("at least one sname must be provided")
	}

	startTime := time.Now().UTC()
	timer := prometheus.NewTimer(Metrics.ResolutionTime)

	nsMap := NewNameServerMap(resolver.RootServers...)
	rootZone := model.NewZone(".", nsMap.Values())

	// Prepare some data structures for later
	arr := zerolog.Arr()
	names := make(map[model.DomainName]uint, len(snames))
	for _, sname := range snames {
		names[sname.Name] = 0
		arr.Str(string(sname.Name))
	}

	// Start the resolving
	logger := resolver.Log.With().Array("originalNames", arr).Logger()

	job := ResolutionJob{
		log:           logger,
		settings:      resolver.Settings,
		strategy:      resolver.Strategy,
		nameServerMap: nsMap,
		Root:          rootZone,
		OriginalNames: common.Keys(names),
		enqueueFunc:   resolver.requestWorker.Enqueue,
		worker:        resolver.requestWorker,
		names:         names,
		cNames:        map[model.DomainName]map[model.DomainName]any{},
		responseQueue: goconcurrentqueue.NewFIFO(),
		openRequests:  new(sync.WaitGroup),
		msgs:          model.NewMessageIdx(),
		beenThereMap: &beenThereMap{
			innerMap: haxmap.New[string, int](512),
			log:      logger,
			maxsize:  resolver.Settings.MaxQueries,
		},
		beenThereMapV2: make(map[mapKey]any, 512),
	}

	// First call OnInit and OnResolveName THEN start the receiveWorker in a separate go routine
	// Avoids race conditions accessing the zone if a response comes in very fast (typically from cache)
	// The receiveWorker might invoke OnResponse while OnStartResolveName is still running.
	job.strategy.OnInit(&job)
	for sname := range job.names {
		job.strategy.OnStartResolveName(&job, sname)
	}

	// Spawn a single analyzer worker. It needs to be a single one, because the zone is not thread-safe.
	// General Idea:
	// RequestWorkers ---> DNS Response
	//	^                   |
	//	|                   v
	//  |               receiveWorker
	//  |                   | invokes
	//  |                   v
	// DNS Requests <--- strategy

	ctx, cancel := common.WithCancel(ctx)
	rcvWorkerDone := make(chan bool)
	ctx.Go(func() {
		job.receiveWorker(ctx)
		rcvWorkerDone <- true
	})

	wait(ctx, job.openRequests) // Wait for all open requests to return or ctx to be canceled

	select {
	case <-ctx.Done():
	default:
		for _, cb := range job.onFinishedCallbacks {
			cb()
		}
		wait(ctx, job.openRequests)
	}

	cancel() // This will cause the receiveWorker to exit
	<-rcvWorkerDone

	duration := timer.ObserveDuration()
	return Result{
		Domains:   snames,
		StartTime: startTime,
		Duration:  duration,
		Zone:      rootZone,
		Msgs:      job.msgs,
	}
}

// OnFinished adds a callback that is executed after the resolution is finished. but befor the receive worker is shut down
func (job *ResolutionJob) OnFinished(cb func()) {
	job.onFinishedCallbacks = append(job.onFinishedCallbacks, cb)
}

// ResolveName adds a name to the list of names that are being resolved and
// starts the resolution process if the name is new.
func (job *ResolutionJob) ResolveName(name model.DomainName) {
	if _, exists := job.names[name]; exists {
		return
	}

	job.names[name] = 0
	job.strategy.OnStartResolveName(job, name)
}

func (job *ResolutionJob) CreateOrGetNameServer(nsName model.DomainName) (*model.NameServer, bool) {
	ns, loaded := job.nameServerMap.CreateOrGet(nsName)

	// This is necessary to support CNAME Nameservers
	// I.e. consider the following: nscname.example.com CNAME ns1.example.org
	// We follow the CNAMEs  and resolve the IPs and add them to the nameserver 'nscname.example.com'
	// Later, we discover that 'ns1.example.org' is also a nameserver (of some other zone)
	// The beentheremap will not allow asking for the A records of ns1.example.org again
	// ==> That means, we have to take them from the msg index.
	// If, however the IPs will be discovered at a point where we know,
	// that both names are nameservers, the IP will be automatically added by the logic in job.AddIPsToNameServer.
	// Future Improvement: If we encode the CNAME relationships in the domain model for the nameservers
	// i.e. we add links between them, we can probably centralize the logic and make it more robust.
	if !loaded {
		ns.AddIPs(common.Keys(job.msgs.GetIps(nsName))...)
	}

	return ns, loaded
}

// AddIPsToNameServer adds the IPs in the Answer of the provided message to the corresponding nameservers
// If the owner of the IP is a name, which is also a CNAME of a nameserver, the IPs are added to said nameserver.
// If, vice versa, the owner of the IP is a name which has a CNAME x and x happens to be a nameserver name (non-compliant, but can happen)
// the IPs are not added to the nameserver x.
func (job *ResolutionJob) AddIPsToNameServer(msg *model.MessageExchange) {
	if msg.Message == nil {
		return
	}
	// Name servers must not be CNAMEs, but it happens, so we need to handle it.
	// If was a name server name we were resolving, add the IPs to the name server.
	for originName := range job.GetCNAMEOrigins(msg.OriginalQuestion.Name) {
		if ns, exists := job.nameServerMap.Get(originName); exists {
			var ips []netip.Addr
			for _, rec := range msg.Message.Answer {
				if aRec, ok := rec.(*dns.A); ok {
					ip, success := netip.AddrFromSlice(aRec.A)
					if !success {
						job.log.Error().Msgf("Failed to convert net.IP %v to netip.Addr", aRec.A)
						continue
					}
					ips = append(ips, ip)
				} else if aaaaRec, ok := rec.(*dns.AAAA); ok {
					ip, success := netip.AddrFromSlice(aaaaRec.AAAA)
					if !success {
						job.log.Error().Msgf("Failed to convert net.IP %v to netip.Addr", aaaaRec.AAAA)
						continue
					}
					ips = append(ips, ip)
				}
			}

			ns.AddIPs(ips...)
		}
	}
}

// ResolveCName acts like ResolveName, but it tracks the current
// length of the CNAME chain and skips resolution if the maximum allowed
// depth is reached.
func (job *ResolutionJob) ResolveCName(cnameOrigin model.DomainName, cnameTarget model.DomainName) {
	targetDepth, exists := job.names[cnameTarget]
	originDepth, _ := job.names[cnameOrigin] // Always exists, we just resolved it

	if targets, ok := job.cNames[cnameOrigin]; !ok {
		job.cNames[cnameOrigin] = make(map[model.DomainName]any, 1)
	} else if _, ok := targets[cnameTarget]; !ok {
		job.log.Warn().
			Str("targetToAdd", string(cnameTarget)).
			Interface("cnameMap", job.cNames).
			Msgf("Multiple CNAMEs (%v) for origin %v.", targets, cnameOrigin)
	}

	job.cNames[cnameOrigin][cnameTarget] = nil

	namesToResolve := make(map[model.DomainName]any)

	// If the target has not been seen, we need to set the length of the CNAME chain
	if !exists {
		job.names[cnameTarget] = originDepth + 1

		if originDepth+1 <= job.settings.MaxCNameDepth {
			namesToResolve[cnameTarget] = nil
		} else if job.settings.MaxCNameDepth > 0 {
			// Only log this if MaxCNameDepth > 0, if the user set it to 0, he knows that this will happen.
			job.log.Warn().Msgf("Reached maximum CNAME depth of %v.", job.settings.MaxCNameDepth)
		}
	}

	// We just found a shorter chain to the target
	// We need to reevaluate the depth of the targets targets recursively
	if originDepth+1 < targetDepth {
		nextTargets := map[model.DomainName]any{cnameTarget: nil}
		newDepth := originDepth

		seenMap := map[model.DomainName]any{cnameTarget: nil}

		for len(nextTargets) > 0 {
			newDepth++
			newNextTargets := make(map[model.DomainName]any)

			for nextTarget := range nextTargets {
				oldDepth := job.names[nextTarget]

				if newDepth < oldDepth {
					job.names[nextTarget] = newDepth
				}

				if oldDepth > job.settings.MaxCNameDepth &&
					newDepth <= job.settings.MaxCNameDepth {
					namesToResolve[nextTarget] = nil
				}

				for target := range job.cNames[nextTarget] {
					// newDepth is always increasing
					// if we have seen something already, skip it - avoids issues with cycles
					if _, seen := seenMap[target]; !seen {
						seenMap[target] = nil
						newNextTargets[target] = nil
					}
				}
			}

			nextTargets = newNextTargets
		}
	}

	for name := range namesToResolve {
		job.strategy.OnStartResolveName(job, name)
	}
}

// IsCNAMEOrSelf returns true if, according to current state, the specified CNAME is
// a cname of the provided origin name.
// As a special case, IsCNAMEOrSelf(x, x) is always true.
func (job *ResolutionJob) IsCNAMEOrSelf(cnameTarget model.DomainName, cnameOrigin model.DomainName) bool {
	_, exists := job.GetCNAMETargets(cnameOrigin)[cnameTarget]
	return exists
}

// GetCNAMETargets returns a list of all names that are (transitive) CNAMEs of the specified origin.
// The result always contains at least the name itself.
func (job *ResolutionJob) GetCNAMETargets(originName model.DomainName) map[model.DomainName]any {
	results := map[model.DomainName]any{originName: nil}
	changed := true

	for changed {
		changed = false
		for origin := range results {
			for target := range job.cNames[origin] {
				if _, exists := results[target]; !exists {
					results[target] = nil
					changed = true
				}
			}
		}
	}

	return results
}

// GetCNAMEOrigins returns a list of all names, for which the specified name is a CNAME.
// The result always contains at least the name itself.
func (job *ResolutionJob) GetCNAMEOrigins(name model.DomainName) map[model.DomainName]any {
	results := map[model.DomainName]any{name: nil}
	changed := true

	for changed {
		changed = false

		for origin := range results {
			for o := range job.cNames {
				for target := range job.cNames[o] {
					if target == origin {
						if _, exists := results[o]; !exists {
							results[o] = nil
							changed = true
						}
					}
				}
			}
		}
	}

	return results
}

// ContainsName returns true if the specified name is being resolved by the job.
// This means that name is either:
//   - the original name that is being resolved,
//   - a name server name that was encountered during the resolution,
//   - additional names like Mail-Servers or _Dmarc that were added
//   - or a CNAME of any of the above
func (job *ResolutionJob) ContainsName(name model.DomainName) bool {
	_, ok := job.names[name]

	return ok
}

func (job *ResolutionJob) GetNamesBelow(name model.DomainName) []model.DomainName {
	var result []model.DomainName
	for n := range job.names {
		if n.IsSubDomainOf(name) {
			result = append(result, n)
		}
	}
	return result
}

// EnqueueOpts are the options for calling EnqueueRequest
type EnqueueOpts struct {
	// DisableTCPFallback disabled TCP for the query. There will be no TCP fallback.
	DisableTCPFallback bool

	// DisableInfraCache tracking the request in the infrastructure cache.
	DisableInfraCache bool

	// SkipCache controls if the query can be answered from the cache.
	// If false, the cache will not be used. The answer of this query
	// will be stored in the cache nevertheless.
	// Usually used in combination with SkipBeenThere
	SkipCache bool

	// SkipBeenThere skips the BeenThere-Checking that avoids asking the same
	// nameserver (-ip) the same query twice during a resolution.
	// If you set this to true, you disable the primary mechanism for avoiding loops, so be careful
	SkipBeenThere bool

	// MaxRetries controls how many times the request should be retried if it fails
	// If nil, the default will be used.
	MaxRetries *uint

	Print bool
}

func (job *ResolutionJob) EnqueueRequestForFutureNameServersAndIps(
	zone *model.Zone,
	question model.Question,
	carryOverArgs any,
	opts EnqueueOpts) {

	k := mapKey{
		q: question,
		z: zone,
	}
	if _, ok := job.beenThereMapV2[k]; ok {
		return
	}
	job.beenThereMapV2[k] = nil

	if !zone.IsNameServerFixed() {
		zone.OnNameServerAdded(question, func(ns *model.NameServer) {
			ns.OnIPAdded(question, func(ip netip.Addr) {
				job.EnqueueRequestIP(ns, ip, question, carryOverArgs, opts)
			})
			job.EnqueueRequest(ns, question, carryOverArgs, opts)
		})
	}

	for _, ns := range zone.GetNameServers() {
		ns.OnIPAdded(question, func(ip netip.Addr) {
			job.EnqueueRequestIP(ns, ip, question, carryOverArgs, opts)
		})
		job.EnqueueRequest(ns, question, carryOverArgs, opts)
	}
}

// EnqueueRequestNowAndForFutureIPs works like EnqueueRequest
// but will also enqueue the request again in the future,
// if a new IP is added to the nameserver.
func (job *ResolutionJob) EnqueueRequestNowAndForFutureIPs(
	ns *model.NameServer,
	question model.Question,
	carryOverArgs any,
	opts EnqueueOpts) {

	ns.OnIPAdded(question, func(ip netip.Addr) {
		job.EnqueueRequestIP(ns, ip, question, carryOverArgs, opts)
	})
	job.EnqueueRequest(ns, question, carryOverArgs, opts)
}

func (job *ResolutionJob) EnqueueRequest(
	ns *model.NameServer,
	question model.Question,
	carryOverArgs any,
	opts EnqueueOpts) {

	for _, ip := range filterIps(ns.IPAddresses.Items(), job.settings.UseV4, job.settings.UseV6) {
		if !opts.SkipBeenThere && job.beenThereMap.track(ip, question.Type, question.Class, question.Name) {
			continue
		}

		job.openRequests.Add(1)

		job.enqueueFunc(Request{
			question:           question,
			nameServerIP:       ip,
			nameServerName:     ns.Name,
			responseQueue:      job.responseQueue,
			disableTCPFallback: opts.DisableTCPFallback,
			skipCache:          opts.SkipCache,
			disableInfraCache:  opts.DisableInfraCache,
			maxRetries:         opts.MaxRetries,
			data:               carryOverArgs,
			log:                job.log,
			do:                 job.settings.GatherDNSSEC,
		})

		if !job.settings.UseAllNameServerIPs {
			return // TODO: we could be a bit smarter (keeping track of which IP is responsive etc. and use that one). But the tool is mostly used with this option=true anyway
		}
	}
}

func (job *ResolutionJob) EnqueueRequestIP(
	ns *model.NameServer,
	ip netip.Addr,
	question model.Question,
	carryOverArgs any,
	opts EnqueueOpts) {

	if !opts.SkipBeenThere && job.beenThereMap.track(ip, question.Type, question.Class, question.Name) {
		return
	}
	if ip.Is6() && !job.settings.UseV6 {
		return
	}
	if ip.Is4() && !job.settings.UseV4 {
		return
	}

	job.openRequests.Add(1)

	job.enqueueFunc(Request{
		question:           question,
		nameServerIP:       ip,
		nameServerName:     ns.Name,
		responseQueue:      job.responseQueue,
		disableTCPFallback: opts.DisableTCPFallback,
		disableInfraCache:  opts.DisableInfraCache,
		skipCache:          opts.SkipCache,
		maxRetries:         opts.MaxRetries,
		data:               carryOverArgs,
		log:                job.log,
		do:                 job.settings.GatherDNSSEC,
	})

	if !job.settings.UseAllNameServerIPs {
		return // TODO: we could be a bit smarter (keeping track of which IP is responsive etc. and use that one). But the tool is mostly used with this option=true anyway
	}
}

// GetLog returns a logger for the job
func (job *ResolutionJob) GetLog() zerolog.Logger {
	// By hiding job.log behind this function, we enforce that every client
	// works on a copy of the log and cannot modify it in the job.
	// So client's can enrich their loggers freely without worrying.
	return job.log
}

func (job *ResolutionJob) GetClosestEncloser(domainName model.DomainName) (*model.Zone, model.DomainName) {
	nameLabels := domainName.GetLabelCount()
	ceZone := job.Root.GetClosestEnclosingZone(domainName)

	zoneLabels := ceZone.Name.GetLabelCount()

	for i := nameLabels; i > zoneLabels; i-- {
		ancestor := domainName.GetAncestor(i)

		for _, ns := range ceZone.NameServers {
			for _, ip := range ns.IPAddresses.Items() {
				for iter := job.msgs.GetMessagesByName(ip, ancestor); iter.HasNext(); {
					exchange := iter.Next()
					if exchange.OriginalQuestion.Type != dns.TypeNS {
						continue
					}

					if exchange.OriginalQuestion.Class != dns.ClassINET {
						continue
					}

					return ceZone, ancestor
				}
			}
		}

	}

	return ceZone, ceZone.Name
}

// receiveWorker receives finished DNS message exchanges and reacts on them by enqueueing follow-up requests.
func (job *ResolutionJob) receiveWorker(ctx common.Context) {
	for {

		var r any
		var err error
		select {
		case <-ctx.Done():
			return
		default:
			// DequeueOrWaitForNextElementContext does not fail if an item is immediately available
			// This leads to the timeout not being respected, if the queue is never empty.
			// That can happen especially for domains with infinite loops configure.
			// Therefore, we need to listen to ctx.Done() ourselves.
			r, err = job.responseQueue.DequeueOrWaitForNextElementContext(ctx)
		}

		if err != nil {
			return // context expired
		}

		response, ok := r.(Response)
		if !ok {
			panic("received unexpected element from queue")
		}

		ns, loaded := job.CreateOrGetNameServer(response.nameServerName)

		if !loaded {
			job.log.Error().
				Interface("response", response).
				Msgf("Nameserver %v did not exist at the time of message reception", response.nameServerName)
		}

		job.msgs.AppendMessage(response.msgExchange)

		// Do not invoke the analyzer for queries that will be retried, only consider "final" responses
		if response.msgExchange.Metadata.IsFinal {
			// patch the enqueue function to set parameters that the strategy.OnResponse does not need to know about.
			corId := response.msgExchange.Metadata.CorrelationId // capture variable outside of func

			enqueueWg := new(sync.WaitGroup)
			job.enqueueFunc = func(request Request) {
				enqueueWg.Add(1)
				request.parentCorrelationId = corId
				go func() {
					// Do not use job.enqueue() here => Will lead to chain of functions
					job.worker.Enqueue(request)
					enqueueWg.Done()
				}()
			}

			// Uncomment for debugging purposes
			// Metrics.ResponseQueueLen.Set(float64(job.responseQueue.GetLen()))

			job.strategy.OnResponse(job, response.msgExchange, ns, response.carryOverArgs)
			enqueueWg.Wait()
			job.openRequests.Done()
		}
	}
}

func filterIps(ipAddresses []netip.Addr, useIPV4 bool, useIPV6 bool) (result []netip.Addr) {
	for _, ip := range ipAddresses {
		if ip.Is6() && useIPV6 {
			result = append(result, ip)
		}
		if ip.Is4() && useIPV4 {
			result = append(result, ip)
		}
	}
	return
}

func wait(ctx common.Context, wg *sync.WaitGroup) {

	r := make(chan struct{})

	// TODO - this goroutine is leaking because wg.Wait() may never finish
	// Maybe we can use this: https://stackoverflow.com/questions/32840687/timeout-for-waitgroup-wait
	go func() {
		wg.Wait()
		r <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return
	case <-r:
		return
	}
}
