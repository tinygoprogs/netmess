package spoof

import (
	"context"
	"errors"
	"net"
	"time"
)

// implements Spoof interface
type Arp struct {
	// packets are injected every InjectRate
	InjectRate time.Duration
	// stops packet injection context
	cancel context.CancelFunc
}

// Either supply one or two ip addresses.
// If only a single ip is supplied, the default gateway of that network is used
// as destination.
func NewArp(n *Network, ip ...string) (*Arp, error) {
	if l := len(ip); l > 2 || l == 0 {
		return nil, errors.New("rtfm")
	}

	var lhost, rhost net.IP
	if len(ip) == 1 {
		lhost = net.ParseIP(ip[0])
		tmp, err := n.Gateway()
		if err != nil {
			return nil, errors.New("gateway unknown")
		}
		rhost = tmp.Addr
	} else if len(ip) == 2 {
		lhost = net.ParseIP(ip[0])
		rhost = net.ParseIP(ip[1])
	} else {
		return nil, errors.New("logic error, must supply 1||2 IPs")
	}
	if lhost == nil || rhost == nil {
		return nil, errors.New("parsing err")
	}

	arp := Arp{
		InjectRate: time.Millisecond * 1000,
	}

	return &arp, nil
}

func (arp *Arp) inject_loop(ctx context.Context) {
	ticker := time.NewTicker(arp.InjectRate)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			arp.inject()
		case <-ctx.Done():
			return
		}
	}
}

// start the injector
func (arp *Arp) Start() error {
	var ctx context.Context
	ctx, arp.cancel = context.WithCancel(context.Background())
	go arp.inject_loop(ctx)
	return nil
}

// stop the injector (and try to restore messed up network)
func (arp *Arp) Stop() {
	arp.cancel()
	// TODO: arp.restore()
}

func (arp *Arp) inject() {
	panic("not impl")
}
