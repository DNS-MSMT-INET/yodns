package model

import (
	"github.com/miekg/dns"
	"net/netip"
)

// MsgIdx is an index holding the exchanged messages.
type MsgIdx struct {
	// TODO - Would be cool if this can be a more generic and extensible index structure
	// I image something like NewMessageIdx().WithIndexThis().AndIndexThat()....
	// and a generic way of querying messages, that is fast if the corresponding indexes exist

	itemsByIP  map[netip.Addr]map[DomainName][]*MessageExchange
	ipsByNames map[DomainName]map[netip.Addr]any
	allNames   map[DomainName]any
	count      int
}

// MsgIterator allows iteration over messages without copying the underlying slices
type MsgIterator struct {
	setIdx  int
	itemIdx int
	set     [][]*MessageExchange
}

func NewMessageIdx() *MsgIdx {
	return &MsgIdx{
		itemsByIP:  make(map[netip.Addr]map[DomainName][]*MessageExchange, 64),
		ipsByNames: make(map[DomainName]map[netip.Addr]any, 32),
		allNames:   make(map[DomainName]any, 64),
	}
}

func (msgIdx *MsgIdx) GetMessagesByNameServer(ns *NameServer) *MsgIterator {
	var sets [][]*MessageExchange
	for _, ip := range ns.IPAddresses.Items() {
		itemsByName := msgIdx.itemsByIP[ip]
		for _, s := range itemsByName {
			sets = append(sets, s)
		}
	}
	return &MsgIterator{set: sets}
}

func (msgIdx *MsgIdx) Count() int {
	return msgIdx.count
}

// GetUniqueNames returns a list of all unique names that are in the index
func (msgIdx *MsgIdx) GetUniqueNames() map[DomainName]any {
	return msgIdx.allNames
}

func (msgIdx *MsgIdx) AppendMessage(msg MessageExchange) {
	msgIdx.count++

	// We have a potential IP address for a name, store it in the ipsByNames index
	if msg.Message != nil && (msg.OriginalQuestion.Type == dns.TypeA || msg.OriginalQuestion.Type == dns.TypeAAAA) {
		for _, rr := range msg.Message.Answer {
			if aRec, ok := rr.(*dns.A); ok {
				dn, err := NewDomainName(aRec.Hdr.Name)
				if err != nil {
					continue
				}
				if _, ok := msgIdx.ipsByNames[dn]; !ok {
					msgIdx.ipsByNames[dn] = make(map[netip.Addr]any)
				}
				if aRec.A == nil {
					continue
				}
				ip, _ := netip.AddrFromSlice(aRec.A)
				msgIdx.ipsByNames[dn][ip] = nil
			} else if aaaaRec, ok := rr.(*dns.AAAA); ok {
				dn, err := NewDomainName(aaaaRec.Hdr.Name)
				if err != nil {
					continue
				}
				if _, ok := msgIdx.ipsByNames[dn]; !ok {
					msgIdx.ipsByNames[dn] = make(map[netip.Addr]any)
				}
				if aaaaRec.AAAA == nil {
					continue
				}
				ip, _ := netip.AddrFromSlice(aaaaRec.AAAA)
				msgIdx.ipsByNames[dn][ip] = nil
			}
		}
	}

	msgsByName, ok := msgIdx.itemsByIP[msg.NameServerIP]
	if !ok {
		msgsByName = make(map[DomainName][]*MessageExchange)
		msgIdx.itemsByIP[msg.NameServerIP] = msgsByName
	}

	msgs, ok := msgsByName[msg.OriginalQuestion.Name]
	if ok {
		msgIdx.allNames[msg.OriginalQuestion.Name] = nil
		msgsByName[msg.OriginalQuestion.Name] = append(msgs, &msg)
		return
	}

	msgs = make([]*MessageExchange, 0, 8)
	msgs = append(msgs, &msg)
	msgsByName[msg.OriginalQuestion.Name] = msgs

}

func (msgIdx *MsgIdx) GetIps(name DomainName) map[netip.Addr]any {
	return msgIdx.ipsByNames[name]
}

func (msgIdx *MsgIdx) GetMessagesByName(ip netip.Addr, name DomainName) *MsgIterator {
	itemsByName, ok := msgIdx.itemsByIP[ip]
	if !ok {
		return &MsgIterator{}
	}

	msgs, _ := itemsByName[name]
	return &MsgIterator{set: [][]*MessageExchange{msgs}}
}

func (msgIdx *MsgIdx) GetMessagesByIP(ip netip.Addr) *MsgIterator {
	var sets [][]*MessageExchange
	itemsByName, ok := msgIdx.itemsByIP[ip]
	if !ok {
		return &MsgIterator{}
	}

	for _, s := range itemsByName {
		sets = append(sets, s)
	}
	return &MsgIterator{set: sets}
}

func (msgIdx *MsgIdx) Iterate() *MsgIterator {
	var sets [][]*MessageExchange
	for _, itemsByName := range msgIdx.itemsByIP {
		for _, s := range itemsByName {
			sets = append(sets, s)
		}
	}
	return &MsgIterator{set: sets}
}

func (iter *MsgIterator) HasNext() bool {
	return iter.setIdx < len(iter.set) && iter.itemIdx < len(iter.set[iter.setIdx])
}

func (iter *MsgIterator) Next() *MessageExchange {
	if iter.setIdx >= len(iter.set) {
		panic("no next item")
	}

	result := iter.set[iter.setIdx][iter.itemIdx]

	iter.itemIdx++
	if iter.itemIdx >= len(iter.set[iter.setIdx]) {
		iter.itemIdx = 0
		iter.setIdx++
	}

	return result
}

func (iter *MsgIterator) ToList() []*MessageExchange {
	// calculate the length to allocate the memory
	l := 0
	for _, set := range iter.set {
		l += len(set)
	}

	// append all items to the array
	result := make([]*MessageExchange, 0, l)
	for _, set := range iter.set {
		result = append(result, set...)
	}

	// mark iterator as finished
	iter.setIdx = len(iter.set)
	return result
}
