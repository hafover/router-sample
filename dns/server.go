package dns

import (
	"encoding/binary"
	"net"
	"sync"

	"lib.za/log"
	"lib.za/thread"

	"proxy-router/cfg"
	"proxy-router/dns/iquery"
	"proxy-router/dns/packet"
)

var svr *server

type server struct {
	udp     *net.UDPConn
	tcp     *net.TCPListener
	pktPool sync.Pool
	cli     *client
	state   *thread.State
}

func Start() {
	conn, err := net.ListenUDP("udp", cfg.DNS.Listen)
	if err != nil {
		log.Fatal("%s", err)
	}
	listen, err := net.ListenTCP("tcp", (*net.TCPAddr)(cfg.DNS.Listen))
	if err != nil {
		log.Fatal("%s", err)
	}
	svr = &server{udp: conn, tcp: listen, state: thread.NewState()}
	svr.pktPool.New = func() any { return &packet.DNS{Data: make([]byte, cfg.DNSBufferSize)} }
	svr.cli = newClient(&svr.pktPool, svr.state)
	go svr.receive()
	go svr.tcpListen()
	log.Info("DNS server listening at: %s", cfg.DNS.Listen.String())
}

func Stop() {
	svr.state.Close()
	svr.state.Wait()
	_ = svr.udp.Close()
	_ = svr.tcp.Close()
	_ = svr.cli.udp.Close()
	log.Info("DNS server exit")
}

func (svr *server) receive() {
	for {
		pkt := svr.pktPool.Get().(*packet.DNS)
		n, addr, err := svr.udp.ReadFrom(pkt.Data[:cap(pkt.Data)])
		if err != nil {
			svr.pktPool.Put(pkt)
			if svr.state.Get() < 0 {
				return
			}
			log.Error("%s", err)
			continue
		}
		pkt.Addr, pkt.Data = addr, pkt.Data[:n]
		thread.Handler[*packet.DNS](func(pkt *packet.DNS, _ *thread.State) {
			defer svr.pktPool.Put(pkt)
			svr.processPacket(pkt)
			if _, err := svr.udp.WriteTo(pkt.Data, pkt.Addr); err != nil {
				log.Error("%s", err)
			}
		}).Do(pkt, svr.state)
	}
}

func (svr *server) tcpListen() {
	for {
		c, err := svr.tcp.Accept()
		if err != nil {
			if svr.state.Get() < 0 {
				return
			}
			log.Error("%s", err)
			continue
		}
		thread.Handler[net.Conn](func(conn net.Conn, state *thread.State) { svr.tcpSession(conn) }).Do(c, svr.state)
	}
}

func (svr *server) tcpSession(conn net.Conn) {
	pkt := svr.pktPool.Get().(*packet.DNS)
	buf := pkt.Data
	defer func() {
		_ = conn.Close()
		pkt.Data = buf
		svr.pktPool.Put(pkt)
	}()
	n, err := conn.Read(pkt.Data[:2])
	if err != nil || n != 2 {
		return
	}
	size := int(binary.BigEndian.Uint16(pkt.Data))
	if size > 1022 {
		log.Error("dns packet over 1024 bytes")
		return
	}
	pkt.Data = pkt.Data[2 : 2+size]
	offset := 0
	for offset < size {
		n, err = conn.Read(pkt.Data[offset:])
		if err != nil {
			log.Error("%s", err)
			return
		}
		offset += n
	}
	svr.processPacket(pkt)
	binary.BigEndian.PutUint16(buf, uint16(len(pkt.Data)))
	if _, err = conn.Write(buf[:2+len(pkt.Data)]); err != nil {
		log.Error("%s", err)
	}
}

func (svr *server) processPacket(pkt *packet.DNS) {
	if code := pkt.DecodeReq(); code != 0 {
		pkt.EncodeErrResp(code)
	} else if pkt.OpCode != packet.OpCodeQuery || len(pkt.Quest) == 0 {
		if !svr.cli.LookupIP(cfg.DNS.NameServer[cfg.DnsDefault], pkt) {
			pkt.EncodeErrResp(packet.RCodeNotImplemented)
		}
	} else {
		svr.handlePacket(pkt)
	}
}

func (svr *server) handlePacket(pkt *packet.DNS) {
	if name := cfg.Hosts.Domain.Match(pkt.Quest); len(name) > 0 {
		if ip, ok := cfg.Hosts.IP[name]; ok {
			pkt.EncodeResp(pkt.Quest, ip)
		} else {
			pkt.EncodeErrResp(packet.RCodeServerFailure)
		}
	} else if ns := svr.ruleMatch(pkt); ns != nil {
		if svr.cli.LookupIP(ns, pkt) {
			an := pkt.DecodeAnswer()
			if len(an) > 0 {
				iquery.SaveIpDomain(an, pkt.Quest)
			} else {
				log.Error("domain (%s) not found ip(%d)", pkt.Quest, pkt.Type)
			}
		} else {
			pkt.EncodeErrResp(packet.RCodeServerFailure)
		}
	}
}

func (svr *server) ruleMatch(pkt *packet.DNS) []cfg.NS {
	var group string
	policy := cfg.Rule.Domain.Match(pkt.Quest)
	if len(policy) == 0 {
		policy = cfg.Rule.Default
	}
	if policy == cfg.PolicyDirect {
		group = cfg.DNS.Rule.Match(pkt.Quest)
	} else if policy == cfg.PolicyReject {
		pkt.EncodeErrResp(packet.RCodeServerFailure)
		return nil
	} else {
		if p, ok := cfg.Policy[policy]; ok {
			group = p.NS
		}
		if len(group) == 0 {
			group = cfg.DNS.Rule.Match(pkt.Quest)
		} else if group == cfg.DnsFakeIp {
			pkt.EncodeResp(pkt.Quest, iquery.GetFakeIp(pkt.Quest))
			return nil
		}
	}
	ns, ok := cfg.DNS.NameServer[group]
	if !ok {
		ns = cfg.DNS.NameServer[cfg.DnsDefault]
	}
	return ns
}
