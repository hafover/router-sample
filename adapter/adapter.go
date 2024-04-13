package adapter

import (
	"net"
	"time"

	"lib.za/log"
	"lib.za/thread"

	"proxy-router/adapter/inbound"
	"proxy-router/adapter/outbound"
	"proxy-router/adapter/udp"
	"proxy-router/cfg"
	"proxy-router/component/iptable"
	"proxy-router/component/pool"
	"proxy-router/dns/iquery"
	"proxy-router/utils"
)

type Outbound interface {
	Dial(addr net.Addr, domain string) (net.Conn, error)
	SendPacket(pkt *udp.Packet, domain string)
	Close()
}

var inst = func() *adapter {
	a := &adapter{
		tcp:     make(chan net.Conn, 1000),
		udp:     make(chan *udp.Packet, 1000),
		udpOut:  thread.NewMap[string, Outbound](0),
		connMgr: newConnMgr(),
		state:   thread.NewState(),
	}
	a.inbound = inbound.NewTProxy(a.tcp, a.udp)
	a.policy = map[string]Outbound{
		cfg.PolicyDirect: outbound.NewDirect(),
		cfg.PolicyReject: outbound.NewReject(),
	}
	a.udpOut.Timeout = time.Minute
	return a
}()

func Start() {
	for name, opt := range cfg.Policy {
		inst.policy[name] = NewPolicy(&opt)
	}
	inst.inbound.Start(inst.state)
	thread.Handler[*adapter]((*adapter).processTCP).Do(inst, inst.state)
	thread.Handler[*adapter]((*adapter).processUDP).Do(inst, inst.state)
}

func Stop() {
	inst.state.Close()
	inst.inbound.Stop()
	inst.state.Wait()
}

type adapter struct {
	tcp     chan net.Conn
	udp     chan *udp.Packet
	inbound *inbound.TProxy
	policy  map[string]Outbound
	udpOut  *thread.Map[string, Outbound]
	connMgr *connMgr
	state   *thread.State
}

func (ad *adapter) processTCP(state *thread.State) {
	for {
		select {
		case conn := <-ad.tcp:
			go ad.handleTCPConn(conn)
		case <-state.Done():
			return
		}
	}
}

func (ad *adapter) handleTCPConn(conn net.Conn) {
	domain := iquery.GetDomain(conn.LocalAddr().(*net.TCPAddr).IP.String())
	policy := ad.ruleMatch(conn.RemoteAddr().(*net.TCPAddr).IP, conn.LocalAddr().(*net.TCPAddr).IP, domain)
	ob, ok := ad.policy[policy]
	if !ok {
		log.Warn("policy %s not found, use direct", policy)
		policy = cfg.PolicyDirect
		ob = ad.policy[cfg.PolicyDirect]
	}
	out, err := ob.Dial(conn.LocalAddr(), domain)
	if err != nil {
		conn.Close()
		if err != outbound.ErrorReject {
			log.Error("TCP %s(%s,%s), %s", conn.LocalAddr().String(), domain, policy, err)
		}
	} else {
		ad.connMgr.appendTCP(newTCPConn(conn, out, domain, policy))
	}
}

func (ad *adapter) processUDP(state *thread.State) {
	for {
		select {
		case pkt := <-ad.udp:
			go ad.handleUDPPacket(pkt)
		case <-state.Done():
			return
		}
	}
}

func (ad *adapter) handleUDPPacket(pkt *udp.Packet) {
	defer udp.PutPacket(pkt)
	dstIp := pkt.DstAddr.IP.String()
	domain := iquery.GetDomain(dstIp)
	if conn := ad.udpOut.Get(dstIp); conn != nil {
		(*conn).SendPacket(pkt, domain)
		return
	}
	policy := ad.ruleMatch(pkt.SrcAddr.IP, pkt.DstAddr.IP, domain)
	ob, ok := ad.policy[policy]
	if !ok {
		log.Warn("policy %s not found, use direct", policy)
		policy = cfg.PolicyDirect
		ob = ad.policy[cfg.PolicyDirect]
	}
	ad.udpOut.Set(dstIp, &ob)
	ob.SendPacket(pkt, domain)
	ad.connMgr.appendUDP(pkt, domain, policy)
}

func (ad *adapter) ruleMatch(src, dst net.IP, domain string) string {
	if policy := cfg.Rule.SrcIp.Match(src); len(policy) > 0 {
		return policy
	}
	if len(domain) > 0 {
		if policy := cfg.Rule.Domain.Match(domain); len(policy) > 0 {
			return policy
		}
	}
	if policy := cfg.Rule.IP.Match(dst); len(policy) > 0 {
		return policy
	}
	return cfg.Rule.Default
}

type connMgr struct {
	tcp      *utils.List[tcpConn]
	tcpQueue chan *tcpConn
	udp      *utils.List[udpConn]
	udpLink  *thread.Map[string, udpConn]
	udpCount *thread.Map[string, int]
}

func newConnMgr() *connMgr {
	cm := &connMgr{
		tcp:      utils.NewList[tcpConn](),
		tcpQueue: make(chan *tcpConn),
		udp:      utils.NewList[udpConn](),
		udpLink:  thread.NewMap[string, udpConn](0),
		udpCount: thread.NewMap[string, int](0),
	}
	cm.udpLink.Timeout = time.Minute
	cm.udpLink.NewValue = func(key string, info any) *udpConn {
		c := info.(*udpConn)
		log.Info("UDP %s --> %s(%s) %s connect",
			c.srcAddr.String(), c.dstAddr.String(), c.domain, c.policy)
		cm.udp.PushBack(c)
		inc := 1
		cm.udpCount.Set(c.srcAddr.String(), &inc)
		if *cm.udpCount.Get(c.srcAddr.String()) > 128 {
			iptable.FilterUDPSrc(c.srcAddr)
		}
		return c
	}
	cm.udpLink.DelValue = func(_ string, c *udpConn, _ bool) {
		log.Info("UDP %s --> %s(%s) %s disconnect",
			c.srcAddr.String(), c.dstAddr.String(), c.domain, c.policy)
		cm.udp.Remove(c)
		dec := -1
		cm.udpCount.Set(c.srcAddr.String(), &dec)
	}
	cm.udpCount.Timeout = time.Minute
	cm.udpCount.SetValue = func(value *int, old *int) *int {
		if old == nil {
			i := 1
			return &i
		}
		*old += *value
		return old
	}
	go cm.tcpClosed()
	return cm
}

func (cm *connMgr) tcpClosed() {
	for c := range cm.tcpQueue {
		log.Info("TCP %s --> %s(%s) %s disconnect",
			c.in.RemoteAddr().String(), c.in.LocalAddr().String(), c.domain, c.policy)
		cm.tcp.Remove(c)
	}
}

func (cm *connMgr) appendTCP(c *tcpConn) {
	log.Info("TCP %s --> %s(%s) %s connect",
		c.in.RemoteAddr().String(), c.in.LocalAddr().String(), c.domain, c.policy)
	cm.tcp.PushBack(c)
}

func (cm *connMgr) appendUDP(pkt *udp.Packet, domain, policy string) {
	uc := &udpConn{srcAddr: pkt.SrcAddr, dstAddr: pkt.DstAddr, domain: domain, policy: policy}
	cm.udpLink.GetEx(pkt.String(), uc)
}

type tcpConn struct {
	in     net.Conn
	out    net.Conn
	domain string
	policy string
}

func newTCPConn(in, out net.Conn, domain, policy string) *tcpConn {
	c := &tcpConn{in: in, out: out, domain: domain, policy: policy}
	go c.link(c.in, c.out, inst.connMgr.tcpQueue)
	go c.link(c.out, c.in, nil)
	return c
}

func (c *tcpConn) link(src net.Conn, dst net.Conn, q chan *tcpConn) {
	buf := pool.GetTCPBuffer()
	defer pool.PutTCPBuffer(buf)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if ew != nil || nr != nw {
				break
			}
		}
		if er != nil {
			break
		}
	}
	_ = src.Close()
	if q != nil {
		q <- c
	}
}

type udpConn struct {
	srcAddr *net.UDPAddr
	dstAddr *net.UDPAddr
	domain  string
	policy  string
}
