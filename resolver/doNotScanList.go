package resolver

import (
	"bufio"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/zmap/go-iptree/iptree"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
)

var doNotScanMu sync.RWMutex

var subnetRegex = regexp.MustCompile(".+/\\d{1,3}")

// DoNotScanList is the list of all IPs and domain names which are exempt from scanning.
var DoNotScanList = doNotScanListWrapper{
	nets:  iptree.New(),
	names: make(map[model.DomainName]int),
}

type doNotScanListWrapper struct {
	nets  *iptree.IPTree
	names map[model.DomainName]int
}

func (list *doNotScanListWrapper) FromFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return list.FromReader(f)
}

func (*doNotScanListWrapper) FromReader(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	result := doNotScanListWrapper{
		nets:  iptree.New(),
		names: make(map[model.DomainName]int),
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		if subnetRegex.Match([]byte(line)) {
			if err := result.AddPrefix(line); err != nil {
				return err
			}

			continue
		}

		dn, err := model.NewDomainName(line)
		if err != nil {
			return fmt.Errorf("value %v in do not scan list is not a valid domain name: %w", line, err)
		}
		result.AddDomainName(dn)
	}

	// Swap
	doNotScanMu.Lock()
	DoNotScanList = result
	doNotScanMu.Unlock()

	return nil
}

// AddDomainName adds a domain name to the do-not-scan-list.
// If the resolver is about to resolve a zone having such a name, it will stop.
// The resolver will also not contact a name server with such a name (given that the name is known at the time)
func (list *doNotScanListWrapper) AddDomainName(domainName model.DomainName) {
	doNotScanMu.Lock()
	list.names[domainName] = 0 // We don't care about the value, the map is effectively used as a set
	doNotScanMu.Unlock()
}

// AddPrefix adds an IP prefix to the do-not-scan-list.
// IPs in that prefix list will never receive a request.
func (list *doNotScanListWrapper) AddPrefix(prefix string) error {
	doNotScanMu.Lock()
	defer doNotScanMu.Unlock()
	if err := list.nets.AddByString(prefix, true); err != nil {
		return fmt.Errorf("value %v in do not scan list is not a valid prefix", prefix)
	}
	return nil

}

// MustNotScan returns true, if either the queried domain name, name server host name or name server IP are on the DoNotScan list.
func (list *doNotScanListWrapper) MustNotScan(q model.Question, nsName model.DomainName, nsIp netip.Addr) bool {
	doNotScanMu.RLock()
	defer doNotScanMu.RUnlock()

	if len(list.names) > 0 {
		for i := 1; i <= q.Name.GetLabelCount(); i++ {
			if _, isContained := list.names[q.Name.GetAncestor(i)]; isContained {
				return true
			}
		}

		for i := 1; i <= nsName.GetLabelCount(); i++ {
			n := nsName.GetAncestor(i)
			if _, isContained := list.names[n]; isContained {
				return true
			}
		}

	}

	v, _, _ := list.nets.GetByString(nsIp.String())
	return v != nil && v.(bool)
}
