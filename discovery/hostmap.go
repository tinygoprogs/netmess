package discovery

import (
	"bytes"
	"net"
)

/*
TODO: Host fingerprinting. Hosts might change mac + ip.
type HostMeta struct {
    ;
}
*/

// used by make() calls
const init_size = 20

type Host struct {
	Addr net.IP
	Mac  net.HardwareAddr
	//Meta HostMeta TODO
}

func (h *Host) String() string {
	return h.Mac.String() + " @ " + h.Addr.String()
}

type HostMap struct {
	ipMap  map[string]*Host
	macMap map[string]*Host
	hosts  []Host
}

func NewHostMap() *HostMap {
	return &HostMap{
		ipMap:  make(map[string]*Host, init_size),
		macMap: make(map[string]*Host, init_size),
		hosts:  make([]Host, 0, init_size),
	}
}

func (hm *HostMap) knownMac(h *Host) (*Host, bool) {
	exists := false
	var rhost *Host
	for _, box := range hm.hosts {
		if bytes.Equal(box.Mac, h.Mac) {
			exists = true
			rhost = &box
			break
		}
	}
	return rhost, exists
}

func (hm *HostMap) Update(h *Host) {
	if hst, known := hm.knownMac(h); known {
		hst.Mac = h.Mac
		h = hst // don't let a new pointer escape here
	} else {
		hm.hosts = append(hm.hosts, *h)
	}
	hm.ipMap[h.Addr.String()] = h
	hm.macMap[h.Mac.String()] = h
}

func (hm *HostMap) Remove(h Host) {
}

func (hm *HostMap) GetIP(ip string) *Host {
	if val, exist := hm.ipMap[ip]; exist {
		return val
	}
	return nil
}
