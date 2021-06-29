package discovery

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
)

var (
	// device name -> interface map
	Ifs map[string]net.Interface
)

func init() {
	ifs, err := net.Interfaces()
	if err != nil {
		log.Fatal("can't get interfaces")
	} else {
		Ifs = make(map[string]net.Interface, 20)
		for _, i := range ifs {
			Ifs[i.Name] = i
		}
	}
}

// Holding a thread-save callback list.
type listenerMap struct {
	lock sync.Mutex
	// TODO: the key here (aka reason) should be a 'type ListenerReason' with a
	// String() method and a 'class' like ReplyListener, InteractiveListener, ??
	funcs map[string]func(gopacket.Packet)
}

func newListenerMap() *listenerMap {
	return &listenerMap{funcs: make(map[string]func(gopacket.Packet), 4)}
}
func (m *listenerMap) Add(desc string, f func(gopacket.Packet)) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if _, exists := m.funcs[desc]; exists {
		return errors.New("exists already")
	}
	m.funcs[desc] = f
	return nil
}
func (m *listenerMap) Remove(desc string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.funcs, desc)
}

type Network struct {
	Dev       *net.Interface
	Localhost Host
	hosts     *HostMap
	handle    *pcap.Handle
	Listeners *listenerMap
}

// Network scope is defined by device.
// Should defer Network.Close().
func NewNetwork(dev string) (*Network, error) {
	device, exists := Ifs[dev]
	if !exists {
		return nil, errors.New("no such interface")
	}

	handle, err := pcap.OpenLive(dev, 0xffff, true, pcap.BlockForever)
	if err != nil {
		handle, err = pcap.OpenLive(dev, 0xffff, false, pcap.BlockForever)
		if err == nil {
			log.Printf("non promiscuous pcap on %s: %v", dev, err)
		}
	}
	if err != nil {
		return nil, errors.New("cannot play with that interface")
	}

	var ip net.IP
	addrs, err := device.Addrs()
	if err != nil {
		log.Printf("device '%s' not 'UP'? err: %v", dev, err)
	} else {
		for _, i := range addrs {
			ip_port := strings.Split(i.String(), "/")
			if ip = net.ParseIP(ip_port[0]).To4(); ip != nil {
				break
			}
		}
	}

	network := Network{
		Dev:       &device,
		hosts:     NewHostMap(),
		Localhost: Host{ip, device.HardwareAddr},
		handle:    handle,
		Listeners: newListenerMap(),
	}

	// immediately start package dispatcher
	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range src.Packets() {
			wg := sync.WaitGroup{}
			network.Listeners.lock.Lock()
			for _, listener := range network.Listeners.funcs {
				wg.Add(1)
				go func() {
					listener(packet)
					wg.Done()
				}()
			}
			network.Listeners.lock.Unlock()
			wg.Wait()
		}
	}()

	return &network, nil
}

// Apply information from "/proc/net/arp".
// Expected format:
//  ip | hw-type | flags | hw-addr | mask | device
func (n *Network) ApplyProcNetARP() {
	tmp, err := ioutil.ReadFile("/proc/net/arp")
	if err != nil {
		return
	}
	content := strings.Split(string(tmp), "\n")
	for _, line := range content[1:] {
		cols := strings.Fields(line)
		if len(cols) != 6 {
			continue
		}
		if cols[5] != n.Dev.Name {
			continue
		}
		mac, err := net.ParseMAC(cols[3])
		if err != nil {
			continue
		}
		n.hosts.Update(&Host{net.ParseIP(cols[0]), mac})
	}
}

// return the Host that the OS thinks is the current gateway
func (n *Network) Gateway() (*Host, error) {
	var host *Host
	tmp, err := ioutil.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	content := strings.Split(string(tmp), "\n")
	for _, line := range content[1:] {
		cols := strings.Fields(line)
		if len(cols) != 11 {
			continue
		}
		if cols[0] != n.Dev.Name {
			continue
		}
		if cols[1] != "00000000" {
			continue
		} // dst
		if cols[7] != "00000000" {
			continue
		} // mask
		// wow this is 'ugly'
		ip_rev, err := hex.DecodeString(cols[2])
		if err != nil {
			return nil, err
		}
		ip32 := binary.BigEndian.Uint32(ip_rev)
		ip_bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ip_bytes, ip32)
		host.Addr = ip_bytes
	}
	return host, nil
}

// Closes the underlying pcap handle.
func (n *Network) Close() {
	if n.handle != nil {
		n.handle.Close()
	}
}

// Return Host information for <ip> on the current Network. If the <ip> is
// unknown we try to find it using ARP.
func (n *Network) GetHostByIP(ip string) (*Host, error) {
	if host := n.hosts.GetIP(ip); host != nil {
		return host, nil
	}
	tmp := net.ParseIP(ip)
	if tmp == nil {
		return nil, errors.New("parsing ip")
	}
	target := tmp.To4()
	if target == nil {
		return nil, errors.New("only ipv4")
	}
	log.Printf("[+] requesting %v", target)

	opts := gopacket.SerializeOptions{
		// XXX maybe add some options, e.g.:
		//FixLengths:       true,
		//ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()

	leth := layers.Ethernet{
		SrcMAC:       n.Localhost.Mac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	larp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   n.Localhost.Mac,
		SourceProtAddress: n.Localhost.Addr,
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    target,
	}

	gopacket.SerializeLayers(buf, opts, &leth, &larp)
	err := n.handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Printf("write err: %v", err)
	}

	// XXX: if the reply gets lost.. maybe delete all listeners from time to time?
	done := make(chan bool, 1)
	reason := "awaiting ARP reply"
	n.Listeners.Add(reason, func(pkt gopacket.Packet) {
		arplayer := pkt.Layer(layers.LayerTypeARP)
		if arplayer == nil {
			return
		}
		arp := arplayer.(*layers.ARP)
		if arp.Operation != layers.ARPReply ||
			!bytes.Equal(arp.SourceProtAddress, target) {
			return
		}
		n.hosts.Update(&Host{target, arp.SourceHwAddress})
		done <- true
	})

	<-done
	n.Listeners.Remove(reason)
	log.Printf("[+] %s: done", reason)

	return n.hosts.GetIP(ip), nil
}
