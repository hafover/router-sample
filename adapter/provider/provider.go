package provider

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"lib.za/log"

	"proxy-router/cfg"
)

var list map[string]*Provider

func init() {
	list = make(map[string]*Provider)
	for k, v := range cfg.Provider {
		list[k] = newProvider(&v)
	}
}

func GetProvider(name string) (*Provider, bool) {
	p, ok := list[name]
	return p, ok
}

func newProvider(opt *cfg.ProxyProvider) *Provider {
	p := &Provider{opt: opt}
	if err := p.refresh(); err != nil {
		log.Fatal("%s", err)
	}
	go func() {
		for {
			time.Sleep(time.Duration(p.opt.Interval) * time.Second)
			if err := p.refresh(); err != nil {
				log.Warn("%s", err)
			} else {
				p.count++
			}
		}
	}()
	return p
}

type Provider struct {
	opt   *cfg.ProxyProvider
	proxy map[string]*cfg.ProxyNode
	cli   http.Client
	count int
}

func (p *Provider) List() []string {
	name := make([]string, 0, len(p.proxy))
	for n := range p.proxy {
		name = append(name, n)
	}
	return name
}

func (p *Provider) Get(name string) (*cfg.ProxyNode, bool) {
	n, ok := p.proxy[name]
	return n, ok
}

func (p *Provider) RefreshCount() int {
	return p.count
}

func (p *Provider) refresh() error {
	data, err := p.fetch()
	if err != nil {
		return err
	}
	p.parse(data)
	if out, err := os.Create(filepath.Join(cfg.WorkDir, "provider."+p.opt.Name+".yaml")); err == nil {
		tmp := struct {
			Proxy []*cfg.ProxyNode `yaml:"proxy"`
		}{Proxy: make([]*cfg.ProxyNode, 0, len(p.proxy))}
		for _, v := range p.proxy {
			tmp.Proxy = append(tmp.Proxy, v)
		}
		sort.Slice(tmp.Proxy, func(i, j int) bool { return tmp.Proxy[i].Name < tmp.Proxy[j].Name })
		enc := yaml.NewEncoder(out)
		_ = enc.Encode(tmp)
		_ = out.Close()
	}
	return nil
}

func (p *Provider) fetch() ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, p.opt.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := bytes.NewBuffer(make([]byte, 0, 32*1024))
	if _, err = io.Copy(buf, resp.Body); err != nil {
		return nil, err
	}
	data := make([]byte, base64.StdEncoding.DecodedLen(buf.Len()))
	n, err := base64.StdEncoding.Decode(data, buf.Bytes())
	return data[:n], err
}

func (p *Provider) parse(data []byte) {
	var beg, end int
	proxy := make(map[string]*cfg.ProxyNode)
	for {
		beg = end
		for data[beg] < 0x20 {
			beg++
			if beg >= len(data) {
				p.proxy = proxy
				return
			}
		}
		end = beg
		for data[end] >= 0x20 {
			end++
			if end >= len(data) {
				break
			}
		}
		info, err := url.Parse(string(data[beg:end]))
		if err != nil {
			log.Warn("%s", err)
		}
		query := info.Query()
		node := &cfg.ProxyNode{Name: info.Fragment, Type: info.Scheme,
			SNI: query.Get("sni"), SCV: query.Get("allowInsecure") == "1", UDP: true}
		idx := strings.IndexByte(info.Host, ':')
		if idx < 0 {
			node.Server = info.Host
			node.Port = 443
		} else {
			node.Server = info.Host[:idx]
			node.Port, _ = strconv.Atoi(info.Host[idx+1:])
		}
		node.Passwd = info.User.Username()
		proxy[node.Name] = node
	}
}
