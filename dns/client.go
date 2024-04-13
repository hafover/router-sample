package dns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"lib.za/log"
	"lib.za/thread"

	"proxy-router/cfg"
	"proxy-router/dns/packet"
)

type message struct {
	*packet.DNS
	ok   bool
	exit chan struct{}
}

type client struct {
	udp     *net.UDPConn
	httpCli *http.Client
	nextId  uint16
	mux     sync.Mutex
	pending *thread.Map[uint16, message]
	pktPool *sync.Pool
}

func newClient(pool *sync.Pool, state *thread.State) *client {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatal("%s", err)
	}
	dialer := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	httpCli := http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 15 * time.Second,
	}
	cli := &client{udp: conn, httpCli: &httpCli, nextId: 100, pktPool: pool}
	cli.pending = thread.NewMap[uint16, message](time.Second)
	cli.pending.Timeout = 30 * time.Second
	cli.pending.DelValue = func(_ uint16, value *message, _ bool) { close(value.exit) }
	go cli.receive(state)
	return cli
}

func (c *client) LookupIP(ns []cfg.NS, pkt *packet.DNS) bool {
	c.mux.Lock()
	c.nextId++
	if c.nextId > 60000 {
		c.nextId = 100
	}
	id := c.nextId
	c.mux.Unlock()
	packet.SetDnsId(pkt.Data, id)
	msg := &message{DNS: pkt, exit: make(chan struct{})}
	c.pending.Set(id, msg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := range ns {
		if ns[i].Type == "IP" {
			c.lookup(ns[i], msg)
		} else if ns[i].Type == "HTTPS" {
			go c.lookupOverHttp(ctx, ns[i], msg)
		}
	}
	<-msg.exit
	return msg.ok
}

func (c *client) lookup(ns cfg.NS, msg *message) {
	if _, err := c.udp.WriteTo(msg.Data, ns.Addr); err != nil {
		log.Error("%s", err)
	}
}

func (c *client) receive(state *thread.State) {
	pkt := c.pktPool.Get().(*packet.DNS)
	defer c.pktPool.Put(pkt)
	for {
		n, _, err := c.udp.ReadFrom(pkt.Data[:cap(pkt.Data)])
		if err != nil {
			if state.Get() < 0 {
				return
			}
			log.Error("%s", err)
			continue
		}
		pkt.Data = pkt.Data[:n]
		c.handlePacket(pkt)
	}
}

func (c *client) lookupOverHttp(ctx context.Context, ns cfg.NS, msg *message) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ns.Host, bytes.NewReader(msg.Data))
	if err != nil {
		log.Error("%s", err)
		return
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")
	resp, err := c.httpCli.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Error("%s", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		pkt := c.pktPool.Get().(*packet.DNS)
		defer c.pktPool.Put(pkt)
		if n, err := resp.Body.Read(pkt.Data[:cap(pkt.Data)]); err != nil {
			log.Error("%s", err)
		} else {
			pkt.Data = pkt.Data[:n]
			c.handlePacket(pkt)
		}
	}
}

func (c *client) handlePacket(pkt *packet.DNS) {
	count, ok := pkt.DecodeResp()
	if !ok {
		return
	}
	msg := c.pending.Get(pkt.ID)
	if msg == nil || (msg.OpCode == packet.OpCodeQuery && count == 0) {
		return
	}
	if msg = c.pending.Pop(pkt.ID); msg != nil {
		msg.Data = msg.Data[:len(pkt.Data)]
		copy(msg.Data, pkt.Data)
		packet.SetDnsId(msg.Data, msg.ID)
		msg.ok = true
		close(msg.exit)
	}
}
