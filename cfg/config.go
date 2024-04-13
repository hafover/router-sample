package cfg

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	"lib.za/jsonx"
	"lib.za/log"

	"proxy-router/component/rule"
)

const (
	DNSBufferSize = 1024
	UDPBufferSize = 4 * 1024
	TCPBufferSize = 16 * 1024
)

const (
	PolicyDirect = "DIRECT"
	PolicyReject = "REJECT"
)

const (
	RuleDomain    = "DOMAIN"
	RuleIpCidr    = "IP-CIDR"
	RuleSrcIpCidr = "SRC-IP-CIDR"
	RuleSet       = "SET"
	RuleDefault   = "DEFAULT"
)

const (
	DnsFakeIp  = "FAKE-IP"
	DnsDefault = "DEFAULT"
)

var (
	WorkDir string
	Port    int
	Hosts   struct {
		Domain rule.Domain
		IP     map[string]net.IP
	}
	Proxy    map[string]ProxyNode
	Provider map[string]ProxyProvider
	Policy   map[string]ProxyPolicy
	Rule     struct {
		Domain  rule.Domain
		IP      rule.IP
		SrcIp   rule.IP
		Default string
	}
	DNS struct {
		Listen     *net.UDPAddr
		NameServer map[string][]NS
		Rule       rule.Domain
		FakeIpCIDR string
		FakeIp     struct {
			Start uint32
			End   uint32
		}
	}
	Profile struct {
		value map[string]string
		mux   sync.Mutex
	}
)

type ProxyNode struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Server  string   `yaml:"server"`
	Port    int      `yaml:"port"`
	Passwd  string   `yaml:"password"`
	ALPN    []string `yaml:"alpn"`
	SNI     string   `yaml:"sni"`
	SCV     bool     `yaml:"skip-cert-verify"`
	UDP     bool     `yaml:"udp"`
	Network string   `yaml:"network"`
}

type ProxyProvider struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	URL      string `yaml:"url"`
	Interval int    `yaml:"interval"`
}

type ProxyPolicy struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	NS       string   `yaml:"ns"`
	Proxy    []string `yaml:"proxy"`
	Provider string   `yaml:"provider"`
}

type NS struct {
	Type string
	Host string
	Addr *net.UDPAddr
}

func init() {
	WorkDir = readStringArg(os.Args, "-d", ".")
	_ = log.SetLogfile(filepath.Join(WorkDir, "server.log"))
	file, err := os.Open(filepath.Join(WorkDir, "config.yaml"))
	if err != nil {
		log.Fatal("%s", err)
	}
	defer file.Close()
	tmp := struct {
		Port     int               `yaml:"port"`
		LogLevel string            `yaml:"log-level"`
		Hosts    map[string]string `yaml:"hosts"`
		Proxy    []ProxyNode       `yaml:"proxy"`
		Provider []ProxyProvider   `yaml:"provider"`
		Policy   []ProxyPolicy     `yaml:"policy"`
		Rule     [][]string        `yaml:"rule"`
		Dns      dnsCfg            `yaml:"dns"`
	}{}
	if err = yaml.NewDecoder(file).Decode(&tmp); err != nil {
		log.Fatal("%s", err)
	}
	Port = tmp.Port
	log.SetLevel(tmp.LogLevel)
	loadHosts(tmp.Hosts)
	loadPolicyCfg(tmp.Proxy, tmp.Provider, tmp.Policy)
	loadDnsCfg(&tmp.Dns)
	loadRule(tmp.Rule)
	loadProfile()
}

func loadHosts(hosts map[string]string) {
	rd := rule.NewDomain()
	g := make(map[string]net.IP)
	for name, ip := range hosts {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			log.Warn("%s, %s, %s", name, ip, err)
			continue
		}
		rd.Append(name, ip)
		g[ip] = addr.AsSlice()
	}
	Hosts.Domain, Hosts.IP = rd, g
}

func loadPolicyCfg(proxy []ProxyNode, provider []ProxyProvider, policy []ProxyPolicy) {
	proxyList := make(map[string]ProxyNode, len(proxy))
	for i := range proxy {
		proxyList[proxy[i].Name] = proxy[i]
	}
	Proxy = proxyList

	providerList := make(map[string]ProxyProvider, len(provider))
	for i := range provider {
		providerList[provider[i].Name] = provider[i]
	}
	Provider = providerList

	policyList := make(map[string]ProxyPolicy)
	for i := range policy {
		policyList[policy[i].Name] = policy[i]
	}
	Policy = policyList
}

func loadRule(list [][]string) {
	domain, ip, srcIp := rule.NewDomain(), rule.NewIp(), rule.NewIp()
	for _, r := range list {
		if len(r) == 2 {
			if r[0] == RuleDefault {
				Rule.Default = r[1]
			}
		} else if len(r) == 3 {
			switch r[0] {
			case RuleDomain:
				domain.Append(r[1], r[2])
			case RuleIpCidr:
				ip.Append(r[1], r[2])
			case RuleSrcIpCidr:
				srcIp.Append(r[1], r[2])
			case RuleSet:
				loadRuleSet(domain, ip, srcIp, r[1], r[2])
			}
		}
	}
	Rule.Domain, Rule.IP, Rule.SrcIp = domain, ip, srcIp
	if len(Rule.Default) == 0 {
		Rule.Default = PolicyDirect
	}
	if Rule.Default == PolicyDirect {
		ip.Append(DNS.FakeIpCIDR, PolicyReject)
	}
}

func loadRuleSet(domain rule.Domain, ip, srcIp rule.IP, filename, policy string) {
	file, err := os.Open(filepath.Join(WorkDir, filename))
	if err != nil {
		log.Fatal("%s", err)
	}
	defer file.Close()
	tmp := struct {
		Rule [][2]string `yaml:"rule"`
	}{}
	if err = yaml.NewDecoder(file).Decode(&tmp); err != nil {
		log.Fatal("%s", err)
	}
	for _, r := range tmp.Rule {
		switch r[0] {
		case RuleDomain:
			domain.Append(r[1], policy)
		case RuleIpCidr:
			ip.Append(r[1], policy)
		case RuleSrcIpCidr:
			srcIp.Append(r[1], policy)
		}
	}
}

type dnsCfg struct {
	Listen      string              `yaml:"listen"`
	NameServer  map[string][]string `yaml:"nameserver"`
	Rule        [][]string          `yaml:"rule"`
	FakeIpRange string              `yaml:"fake-ip-range"`
}

func loadDnsCfg(dns *dnsCfg) {
	var err error
	DNS.Listen, err = net.ResolveUDPAddr("udp", dns.Listen)
	if err != nil || !DNS.Listen.IP.IsPrivate() {
		log.Fatal("dns listen addr invalid, %s", err)
	}
	DNS.NameServer = make(map[string][]NS)
	for p, n := range dns.NameServer {
		g := make([]NS, 0)
		for i := range n {
			ns := NS{Host: n[i]}
			if strings.HasPrefix(ns.Host, "https://") {
				ns.Type = "HTTPS"
			} else {
				ns.Type, ns.Addr = "IP", &net.UDPAddr{IP: net.ParseIP(ns.Host), Port: 53}
				if ns.Addr.IP == nil {
					log.Fatal("name server %s invalid", ns.Host)
				}
			}
			g = append(g, ns)
		}
		if len(g) > 0 {
			DNS.NameServer[p] = g
		}
	}
	if _, ok := DNS.NameServer[DnsDefault]; !ok {
		log.Fatal("name server default group not found")
	}
	DNS.Rule = rule.NewDomain()
	for _, r := range dns.Rule {
		if len(r) != 2 || !DNS.Rule.Append(r[0], r[1]) {
			log.Warn("name server rule %v invalid", r)
		}
	}
	if pre, err := netip.ParsePrefix(dns.FakeIpRange); err == nil && pre.Addr().Is4() {
		ip, bits := pre.Addr().As4(), pre.Bits()
		DNS.FakeIp.Start = (binary.BigEndian.Uint32(ip[:]) & (math.MaxUint32 << (32 - bits))) + 1
		DNS.FakeIp.End = DNS.FakeIp.Start + (1 << (32 - bits)) - 1
		DNS.FakeIpCIDR = dns.FakeIpRange
	} else {
		DNS.FakeIp.Start, DNS.FakeIp.End = 0xC6120001, 0xC6130000
		DNS.FakeIpCIDR = "198.18.0.1/16"
	}
}

func loadProfile() {
	Profile.value = make(map[string]string)
	if data, err := os.ReadFile(filepath.Join(WorkDir, "profile.json")); err == nil {
		if err = jsonx.Unmarshal(data, &Profile.value); err != nil {
			log.Warn("%s", err)
		}
	}
}

func SaveProfile() {
	doc := jsonx.Marshal(Profile.value, nil)
	if err := os.WriteFile(filepath.Join(WorkDir, "profile.json"), doc, 0644); err != nil {
		log.Error("%s", err)
	}
}

func GetProfile(key string) (string, bool) {
	Profile.mux.Lock()
	defer Profile.mux.Unlock()
	v, ok := Profile.value[key]
	return v, ok
}

func SetProfile(key, value string) {
	Profile.mux.Lock()
	defer Profile.mux.Unlock()
	Profile.value[key] = value
}

func readStringArg(args []string, key string, val string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == key {
			i++
			if i < len(args) {
				return args[i]
			}
			break
		}
	}
	return val
}
