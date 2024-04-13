package inbound

import (
	"encoding/binary"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	"lib.za/log"
	"lib.za/thread"

	"proxy-router/adapter/udp"
	"proxy-router/cfg"
)

type TProxy struct {
	tl  *net.TCPListener
	ul  *net.UDPConn
	tcp chan<- net.Conn
	udp chan<- *udp.Packet
}

func NewTProxy(tcp chan<- net.Conn, udp chan<- *udp.Packet) *TProxy {
	return &TProxy{tcp: tcp, udp: udp}
}

func (ib *TProxy) Start(state *thread.State) {
	ib.startTCP(state)
	ib.startUDP(state)
	log.Info("inbound tproxy://:%d create success", cfg.Port)
}

func (ib *TProxy) Stop() {
	_ = ib.tl.Close()
	_ = ib.ul.Close()
	log.Info("inbound tproxy://:%d destroy", cfg.Port)
}

func (ib *TProxy) startTCP(state *thread.State) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: cfg.Port})
	if err != nil {
		log.Fatal("%s", err)
	}
	ib.setsockopt(l)
	ib.tl = l
	thread.Handler[*TProxy]((*TProxy).tcpListen).Do(ib, state)
}

func (ib *TProxy) tcpListen(state *thread.State) {
	for {
		c, err := ib.tl.Accept()
		if err != nil {
			if state.Get() < 0 {
				return
			}
			log.Error("%s", err)
			continue
		}
		ib.tcp <- c
	}
}

func (ib *TProxy) startUDP(state *thread.State) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.Port})
	if err != nil {
		log.Fatal("%s", err)
	}
	ib.setsockopt(c)
	ib.ul = c
	thread.Handler[*TProxy]((*TProxy).updListen).Do(ib, state)
}

func (ib *TProxy) updListen(state *thread.State) {
	oob := make([]byte, 1024)
	for {
		pkt := udp.GetPacket()
		n, n2, _, lAddr, err := ib.ul.ReadMsgUDPAddrPort(pkt.Data[:cap(pkt.Data)], oob)
		if err != nil {
			udp.PutPacket(pkt)
			if state.Get() < 0 {
				return
			}
			log.Error("%s", err)
			continue
		}
		hdr, data, _, err := unix.ParseOneSocketControlMessage(oob[:n2])
		if err != nil {
			udp.PutPacket(pkt)
			log.Error("%s", err)
			continue
		}
		if hdr.Level == unix.SOL_IP && hdr.Type == unix.IP_ORIGDSTADDR {
			pkt.DstAddr = &net.UDPAddr{IP: make(net.IP, 4), Port: int(binary.BigEndian.Uint16(data[2:4]))}
			copy(pkt.DstAddr.IP, data[4:8])
		} else if hdr.Level == unix.SOL_IPV6 && hdr.Type == unix.IPV6_ORIGDSTADDR {
			pkt.DstAddr = &net.UDPAddr{IP: make(net.IP, 16), Port: int(binary.BigEndian.Uint16(data[2:4]))}
			copy(pkt.DstAddr.IP, data[8:24])
		} else {
			udp.PutPacket(pkt)
			log.Error("unable to get udp destination address")
			continue
		}
		pkt.Data, pkt.SrcAddr = pkt.Data[:n], &net.UDPAddr{IP: lAddr.Addr().AsSlice(), Port: int(lAddr.Port())}
		ib.udp <- pkt
	}
}

func (ib *TProxy) setsockopt(c syscall.Conn) {
	rc, err := c.SyscallConn()
	if err != nil {
		log.Fatal("%s", err)
	}
	_ = rc.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			log.Fatal("%s", err)
		}
		if err := syscall.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			log.Fatal("%s", err)
		}
		if err := syscall.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
			log.Fatal("%s", err)
		}
		if err := syscall.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			log.Debug("%s", err)
		}
		if err := syscall.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_ORIGDSTADDR, 1); err != nil {
			log.Debug("%s", err)
		}
	})
}
