package iquery

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"lib.za/jsonx"
	"lib.za/log"
	"lib.za/thread"

	"proxy-router/cfg"
)

var inst = invertQuery{}

type invertQuery struct {
	cache  *thread.Map[string, string]
	fake   *thread.Map[string, net.IP]
	nextIp uint32
}

func init() {
	inst.cache = thread.NewMap[string, string](0)
	inst.cache.Timeout = 24 * time.Hour
	inst.fake = thread.NewMap[string, net.IP](0)
	inst.fake.Timeout, inst.fake.Expire = 0, 5*time.Minute
	inst.fake.NewValue = func(key string, _ any) *net.IP {
		inst.nextIp++
		if inst.nextIp&0xff == 0xff {
			inst.nextIp += 2
		}
		if inst.nextIp >= cfg.DNS.FakeIp.End {
			inst.nextIp = cfg.DNS.FakeIp.Start
		}
		addr := inst.nextIp
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, addr)
		inst.cache.Set(netip.AddrFrom4([4]byte(ip)).String(), &key)
		return &ip
	}
	inst.nextIp = cfg.DNS.FakeIp.Start
}

func GetFakeIp(domain string) net.IP {
	return *inst.fake.Get(domain)
}

func GetDomain(ip string) string {
	if domain := inst.cache.Get(ip); domain != nil {
		return *domain
	}
	return ""
}

func SaveIpDomain(ip []net.IP, domain string) {
	for i := range ip {
		inst.cache.Set(ip[i].String(), &domain)
	}
}

func Load() {
	if data, err := os.ReadFile(filepath.Join(cfg.WorkDir, "iquery.json")); err == nil {
		var info struct {
			NextIp uint32 `json:"next_ip"`
			Cache  []struct {
				Ip     string `json:"ip"`
				Domain string `json:"domain"`
			} `json:"cache"`
		}
		if err = jsonx.Unmarshal(data, &info); err == nil {
			inst.nextIp = info.NextIp
			for i := range info.Cache {
				inst.cache.Set(info.Cache[i].Ip, &info.Cache[i].Domain)
			}
		}
		_ = os.Remove(filepath.Join(cfg.WorkDir, "iquery.json"))
	}
}

func Save() {
	doc := jsonx.AppendDocumentStart(make([]byte, 0, 4*1024))
	doc = jsonx.AppendUintElement(doc, "next_ip", inst.nextIp)
	doc = jsonx.AppendArrayElementStart(doc, "cache")
	inst.cache.Dump(func(key string, value *string) {
		doc = jsonx.AppendDocumentStart(doc)
		doc = jsonx.AppendStringElement(doc, "ip", key)
		doc = jsonx.AppendStringElement(doc, "domain", *value)
		doc = jsonx.AppendDocumentEnd(doc)
	})
	doc = jsonx.AppendArrayEnd(doc)
	doc = jsonx.AppendDocumentEnd(doc)
	if err := os.WriteFile(filepath.Join(cfg.WorkDir, "iquery.json"), doc.Bytes(), 0644); err != nil {
		log.Error("%s", err)
	}
}
