package model

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"strconv"
	"strings"

	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Zone represents a DNS zone
type Zone struct {
	// The name of the zone
	Name DomainName

	// The parent zone
	Parent *Zone

	// Subzones of the zone
	Subzones []*Zone

	// The authoritative name servers of the zone.
	NameServers []*NameServer

	// If a zone is marked as "trusted" one of the nameservers will be fixed and use for all further queries.
	fixedNameServers []*NameServer

	// Callbacks invoked when a new name server is added to the zone.
	onNameServerAdded map[any]func(ns *NameServer)
}

func NewZone(name DomainName, nameservers []*NameServer) *Zone {
	return &Zone{
		Name:              name,
		NameServers:       nameservers,
		onNameServerAdded: make(map[any]func(ns *NameServer)),
	}
}

// GoToRoot return the root zone.
func (zone *Zone) GoToRoot() *Zone {
	if zone.Parent == nil {
		return zone
	}

	return zone.Parent.GoToRoot()
}

func (zone *Zone) OnNameServerAdded(key any, callback func(ns *NameServer)) {
	zone.onNameServerAdded[key] = callback
}

func (zone *Zone) OnNameServerAddedOnce(key any, callback func(ns *NameServer)) {
	zone.onNameServerAdded[key] = func(ns *NameServer) {
		callback(ns)
		delete(zone.onNameServerAdded, key)
	}
}


// GetRecords returns all the distinct resource records that could be retrieved for the zone.
// It can be expensive, use with care.
func (zone *Zone) GetRecords(msgSet *MsgIdx) []dns.RR {
	rrmap := make(map[string]dns.RR)
	for _, ns := range zone.NameServers {
		for iter := msgSet.GetMessagesByNameServer(ns); iter.HasNext(); {
			exchange := iter.Next()
			if exchange.Message == nil {
				continue
			}

			for _, rr := range exchange.Message.Answer {
				rrmap[getKey(rr)] = rr
			}
			for _, rr := range exchange.Message.Ns {
				rrmap[getKey(rr)] = rr
			}
			for _, rr := range exchange.Message.Extra {
				rrmap[getKey(rr)] = rr
			}
		}
	}
	return common.Values(rrmap)
}

func getKey(rr dns.RR) string {
	var builder strings.Builder
	builder.WriteString(rr.Header().Name)
	builder.WriteString(strconv.Itoa(int(rr.Header().Rrtype)))
	builder.WriteString(strconv.Itoa(int(rr.Header().Class)))
	builder.WriteString(GetRRValue(rr))
	return builder.String()
}

// GetClosestEnclosingZone Returns the zone whose name is the "the longest existing ancestor of a name." [rfc5155] of the provided name.
func (zone *Zone) GetClosestEnclosingZone(domainName DomainName) *Zone {
	for _, subzone := range zone.Subzones {
		if domainName.IsSubDomainOf(subzone.Name) {
			return subzone.GetClosestEnclosingZone(domainName)
		}
	}
	return zone
}

// AppendNameServers appends to the list of the zones name servers.
func (zone *Zone) AppendNameServers(nameServers ...*NameServer) {
	for _, ns := range nameServers {
		zone.AppendNameServer(ns)
	}
}

// IsParentOf returns true if the zone is the direct parent of the child.
func (zone *Zone) IsParentOf(child *Zone) bool {
	for _, sz := range zone.Subzones {
		if sz == child {
			return true
		}
	}
	return false
}

func (zone *Zone) HasNameServer(nameServer *NameServer) bool {
	return zone.HasNameServerWithName(nameServer.Name)
}

func (zone *Zone) HasNameServerWithName(nsName DomainName) bool {
	for _, ns := range zone.NameServers {
		if nsName == ns.Name {
			return true
		}
	}
	return false
}

func (zone *Zone) AppendNameServer(nameServer *NameServer) bool {
	if nameServer == nil {
		panic("cannot append nil nameserver")
	}

	for _, ns := range zone.NameServers {
		if nameServer.Name == ns.Name {
			// We add the IPs to make sure they are not lost.
			ns.AddIPs(nameServer.IPAddresses.Items()...)

			return false
		}
	}

	zone.NameServers = append(zone.NameServers, nameServer)
	for _, callback := range zone.onNameServerAdded {
		callback(nameServer)
	}

	return true
}

// FixNameServer picks a n random name servers from the zone to be used for all further queries.
// The fixed nameserver will be returned via GetNameServers()
// Repeated calls to FixNameServer will have no effect.
func (zone *Zone) FixNameServer(seed string, n int) {
	if zone.fixedNameServers != nil {
		return
	}

	// First sort, so the seeded shuffle always produces the same result (same initial condition)
	slices.SortStableFunc(zone.NameServers, func(a, b *NameServer) int {
		return CompareDomainName(string(a.Name), string(b.Name))
	})

	// Now shuffle
	h := fnv.New32a()
	h.Write([]byte(seed))
	r := rand.New(rand.NewSource(int64(h.Sum32())))
	r.Shuffle(len(zone.NameServers), func(i, j int) { zone.NameServers[i], zone.NameServers[j] = zone.NameServers[j], zone.NameServers[i] })

	zone.fixedNameServers = slices.Clone(zone.NameServers[:common.MinInt(n, len(zone.NameServers))])
}

// IsNameServerFixed returns true if a name server was fixed via FixNameServer.
func (zone *Zone) IsNameServerFixed() bool {
	return zone.fixedNameServers != nil
}

// GetNameServers returns the name servers of the zone.
// If FixNameServer was called, only the fixed name server will be returned.
func (zone *Zone) GetNameServers() []*NameServer {
	if zone.fixedNameServers != nil {
		return zone.fixedNameServers
	}
	return zone.NameServers
}

// CreateOrGetSubzone returns the non-proper subzone whose name is equal to the provided domain name
// or creates one if no such zone exists yet. This method can also return the zone itself, if the provided name
// is equal to the zone name. The second return value indicates, whether
// the subzone was loaded (true) or created (false)
func (zone *Zone) CreateOrGetSubzone(name DomainName) (z *Zone, loaded bool, err error) {
	// If not a subdomain (mind that .xyz is considered a subdomain of .xyz)
	if !name.IsSubDomainOf(zone.Name) {
		return nil, false, fmt.Errorf("cannot create subzone '%v' in zone '%v' because the name does not indicate a subzone relationship", name, zone.Name)
	}

	if name.Equal(zone.Name) {
		return zone, true, nil
	}

	// If such a zone exists, return it.
	for _, subzone := range zone.Subzones {
		if subzone.Name.Equal(name) {
			return subzone, true, nil
		}

		if name.IsSubDomainOf(subzone.Name) {
			return subzone.CreateOrGetSubzone(name)
		}
	}

	// Else, add it.
	subzone := Zone{
		Name:              name,
		Parent:            zone,
		onNameServerAdded: make(map[any]func(ns *NameServer)),
	}
	zone.Subzones = append(zone.Subzones, &subzone)

	return &subzone, false, nil
}

func (zone *Zone) RemoveSubzone(name DomainName) bool {
	for i, subzone := range zone.Subzones {
		if subzone.Name.Equal(name) {
			zone.Subzones = slices.Delete(zone.Subzones, i, i)
			return true
		}
	}
	return false
}

// Flatten returns a flat array of zones, including this zone, subzones, subzones of subzones etc.
func (zone *Zone) Flatten() []*Zone {
	zones := []*Zone{zone}

	for _, sz := range zone.Subzones {
		zones = append(zones, sz.Flatten()...)
	}

	return zones
}

func (zone *Zone) GetDepth() int {
	if zone.Parent == nil {
		return 0
	}
	return zone.Parent.GetDepth() + 1
}

func (zone *Zone) GetNameServersRecursive() []*NameServer {
	servers := map[*NameServer]any{}
	for _, ns := range zone.NameServers {
		servers[ns] = nil
	}

	for _, sz := range zone.Subzones {
		for _, ns := range sz.GetNameServersRecursive() {
			servers[ns] = nil
		}
	}

	return common.Keys(servers)
}

// GetNames extracts a list of all unique names that are in the zone
func (zone *Zone) GetNames(msgSet *MsgIdx) []DomainName {
	var result []DomainName
	for name := range msgSet.GetUniqueNames() {
		if zone.GetClosestEnclosingZone(name) == zone {
			result = append(result, name)
		}
	}
	return result
}

func (zone *Zone) GetZoneDependencies() map[DomainName]any {
	dep := make(map[DomainName]any)
	zone.AddZoneDependencies(dep)
	return dep
}

func (zone *Zone) AddZoneDependencies(seenMap map[DomainName]any) {
	seenMap[zone.Name] = nil
	for _, ns := range zone.NameServers {
		nsParentZone := zone.GoToRoot().GetClosestEnclosingZone(ns.Name)
		if _, seen := seenMap[nsParentZone.Name]; !seen {
			nsParentZone.AddZoneDependencies(seenMap)
		}
	}

	if zone.Parent != nil {
		if _, seen := seenMap[zone.Parent.Name]; !seen {
			zone.Parent.AddZoneDependencies(seenMap)
		}
	}
}
