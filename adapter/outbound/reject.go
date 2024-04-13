package outbound

import (
	"errors"
	"net"

	"lib.za/log"

	"proxy-router/adapter/udp"
)

var ErrorReject = errors.New("reject")

func NewReject() *Reject {
	return &Reject{}
}

type Reject struct{}

func (ob *Reject) Dial(addr net.Addr, domain string) (net.Conn, error) {
	log.Info("TCP %s(%s) reject", addr.String(), domain)
	return nil, ErrorReject
}

func (ob *Reject) SendPacket(pkt *udp.Packet, domain string) {
	log.Info("UDP %s(%s) reject", pkt.DstAddr.String(), domain)
}

func (ob *Reject) Close() {}
