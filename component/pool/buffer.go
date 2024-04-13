package pool

import (
	"sync"

	"proxy-router/cfg"
)

var bufPool = func() *buffer {
	b := &buffer{}
	b.udpBuf.New = func() any { return make([]byte, cfg.UDPBufferSize) }
	b.tcpBuf.New = func() any { return make([]byte, cfg.TCPBufferSize) }
	return b
}()

type buffer struct {
	udpBuf sync.Pool
	tcpBuf sync.Pool
}

func GetUDPBuffer() []byte    { return bufPool.udpBuf.Get().([]byte)[:cfg.UDPBufferSize] }
func PutUDPBuffer(buf []byte) { bufPool.udpBuf.Put(buf) }
func GetTCPBuffer() []byte    { return bufPool.tcpBuf.Get().([]byte)[:cfg.TCPBufferSize] }
func PutTCPBuffer(buf []byte) { bufPool.tcpBuf.Put(buf) }
