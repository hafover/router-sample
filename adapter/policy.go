package adapter

import (
	"fmt"
	"net"
	"time"

	"lib.za/log"
	"lib.za/thread"

	"proxy-router/adapter/provider"
	"proxy-router/adapter/udp"
	"proxy-router/cfg"
)

func NewPolicy(opt *cfg.ProxyPolicy) *Policy {
	p := &Policy{opt: opt}
	if len(p.opt.Provider) > 0 {
		if tmp, ok := provider.GetProvider(p.opt.Provider); !ok {
			log.Warn("proxy provider %s not found", p.opt.Provider)
		} else {
			p.provider = tmp
			if len(p.opt.Proxy) == 0 {
				p.opt.Proxy = p.provider.List()
			}
		}
	}
	p.proxy = p.getProxy()
	p.discard = thread.NewPool[int, Outbound](func(ob *Outbound) { (*ob).Close() })
	go p.refresh()
	return p
}

type Policy struct {
	opt      *cfg.ProxyPolicy
	provider *provider.Provider
	proxy    Outbound
	discard  *thread.Pool[int, Outbound]
}

func (ob *Policy) Dial(addr net.Addr, domain string) (net.Conn, error) {
	return ob.proxy.Dial(addr, domain)
}

func (ob *Policy) SendPacket(pkt *udp.Packet, domain string) {
	ob.proxy.SendPacket(pkt, domain)
}

func (ob *Policy) Close() {}

func (ob *Policy) getProxy() Outbound {
	switch ob.opt.Type {
	case "select":
		name, ok := cfg.GetProfile(fmt.Sprintf("policy.%s.select", ob.opt.Name))
		if !ok {
			name = ob.opt.Proxy[0]
			cfg.SetProfile(fmt.Sprintf("policy.%s.select", ob.opt.Name), name)
		}
		if name == cfg.PolicyDirect {
			return inst.policy[cfg.PolicyDirect]
		} else if name == cfg.PolicyReject {
			return inst.policy[cfg.PolicyReject]
		} else if ob.provider != nil {
			// if opt, ok := ob.provider.Get(name); ok {
			// }
		}
		// if opt, ok := cfg.Proxy[name]; ok {
		// }
	default:
	}
	return inst.policy[cfg.PolicyReject]
}

func (ob *Policy) refresh() {
	if ob.provider == nil {
		return
	}
	count := ob.provider.RefreshCount()
	for {
		time.Sleep(time.Minute)
		if count != ob.provider.RefreshCount() {
			count = ob.provider.RefreshCount()
			ob.discard.Push(&ob.proxy)
			ob.proxy = ob.getProxy()
		}
	}
}
