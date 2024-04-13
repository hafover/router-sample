package outbound

import (
	"errors"
	"io"
	"net"
	"time"

	"lib.za/log"
	"lib.za/thread"

	"proxy-router/adapter/udp"
	"proxy-router/component/pool"
)

type packetConn struct {
	srcAddr *net.UDPAddr
	conn    net.PacketConn
}

func (pc *packetConn) receivePacket() {
	buf := pool.GetUDPBuffer()
	defer pool.PutUDPBuffer(buf)
	for {
		n, addr, err := pc.conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				log.Error("%s", err)
			}
			return
		}
		if conn := udp.GetPacketConn(addr.String()); conn != nil {
			if _, err = conn.WriteTo(buf[:n], pc.srcAddr); err != nil {
				log.Error("%s", err)
				return
			}
		}
	}
}

func NewDirect() *Direct {
	d := &Direct{chain: thread.NewMap[string, packetConn](0)}
	d.chain.Timeout = time.Minute
	d.chain.SlowValue = func(key string, info interface{}) *packetConn {
		pc := info.(*packetConn)
		var err error
		if pc.conn, err = net.ListenUDP("udp", nil); err != nil {
			log.Error("%s", err)
			return nil
		}
		go pc.receivePacket()
		return pc
	}
	d.chain.DelValue = func(_ string, pc *packetConn, _ bool) { _ = pc.conn.Close() }
	return d
}

type Direct struct {
	chain *thread.Map[string, packetConn]
}

func (ob *Direct) Dial(addr net.Addr, _ string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.Dial(addr.Network(), addr.String())
}

func (ob *Direct) SendPacket(pkt *udp.Packet, _ string) {
	info := &packetConn{srcAddr: pkt.SrcAddr}
	if pc := ob.chain.GetEx(pkt.SrcAddr.String(), info); pc != nil {
		if _, err := pc.conn.WriteTo(pkt.Data, pkt.DstAddr); err != nil {
			log.Error("%s", err)
		}
	}
}

func (ob *Direct) Close() {}
