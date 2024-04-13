package udp

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"lib.za/log"
	"lib.za/thread"

	"proxy-router/cfg"
)

const hexTable = "0123456789abcdef"

var pktPool = sync.Pool{}
var pktConn *thread.Map[string, net.PacketConn]

func init() {
	pktPool.New = func() any { return &Packet{Data: make([]byte, cfg.UDPBufferSize)} }
	pktConn = thread.NewMap[string, net.PacketConn](0)
	pktConn.Timeout = time.Minute
	pktConn.SlowValue = func(addr string, _ any) *net.PacketConn {
		conn, err := listenPacket(addr)
		if err != nil {
			log.Error("%s", err)
			return nil
		}
		return &conn
	}
	pktConn.DelValue = func(_ string, conn *net.PacketConn, _ bool) { _ = (*conn).Close() }
}

type Packet struct {
	SrcAddr *net.UDPAddr
	DstAddr *net.UDPAddr
	Data    []byte
}

func (p *Packet) String() string {
	buf := make([]byte, 128)
	idx := 0
	for _, b := range p.SrcAddr.IP {
		buf[idx] = hexTable[b>>4]
		buf[idx+1] = hexTable[b&0xf]
		idx += 2
	}
	buf[idx] = ':'
	idx += 1
	for port := p.SrcAddr.Port; port > 0; port = port >> 4 {
		buf[idx] = hexTable[port&0xf]
		idx += 1
	}
	buf[idx] = '|'
	idx += 1
	for _, b := range p.DstAddr.IP {
		buf[idx] = hexTable[b>>4]
		buf[idx+1] = hexTable[b&0xf]
		idx += 2
	}
	buf[idx] = ':'
	idx += 1
	for port := p.DstAddr.Port; port > 0; port = port >> 4 {
		buf[idx] = hexTable[port&0xf]
		idx += 1
	}
	return string(buf[:idx])
}

func GetPacket() *Packet {
	return pktPool.Get().(*Packet)
}

func PutPacket(pkt *Packet) {
	pktPool.Put(pkt)
}

func GetPacketConn(addr string) net.PacketConn {
	if conn := pktConn.Get(addr); conn != nil {
		return *conn
	}
	return nil
}

func listenPacket(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				log.Error("%s", err)
			}
			if err := syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				log.Error("%s", err)
			}
			if err := syscall.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
				log.Error("%s", err)
			}
			_ = syscall.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		})
	}}
	return lc.ListenPacket(context.Background(), "udp", addr)
}
