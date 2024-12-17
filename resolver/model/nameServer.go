package model

import (
	"net/netip"

	"github.com/DNS-MSMT-INET/yodns/resolver/common"
)

// NameServer represents a dns name server.
type NameServer struct {
	Name DomainName

	// IPAddresses contains the set of unique addresses that were found for this name server.
	IPAddresses common.CompSet[netip.Addr]

	onIPAddedCallbacks map[any]func(ip netip.Addr)
}

func NewNameServer(name DomainName) *NameServer {
	return &NameServer{
		Name:               name,
		IPAddresses:        common.NewCompSet[netip.Addr](),
		onIPAddedCallbacks: make(map[any]func(ip netip.Addr)),
	}
}

func (ns *NameServer) OnIPAdded(key any, callback func(ip netip.Addr)) {
	ns.onIPAddedCallbacks[key] = callback
}

func (ns *NameServer) RemoveOnIPAdded(key any) {
	delete(ns.onIPAddedCallbacks, key)
}


// AddIPs adds new IPs to the set of addresses of this server.
func (ns *NameServer) AddIPs(ipAddresses ...netip.Addr) {
	for _, ip := range ipAddresses {
		if !ns.IPAddresses.Contains(ip) {
			ns.IPAddresses.Add(ip)
			for _, callback := range ns.onIPAddedCallbacks {
				callback(ip)
			}
		}
	}
}
