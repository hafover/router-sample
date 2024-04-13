package iptable

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"lib.za/log"

	"proxy-router/cfg"
)

const (
	proxyFWMark = 666
	proxyTable  = 666
)

var mux sync.Mutex

func Setup() {
	execCmd("/bin/bash", "-c", "modprobe xt_TPROXY")
	execCmd("/bin/bash", "-c", "lsmod | grep xt_TPROXY")
	_, _ = removeProxyRule()
	appendProxyRule()
}

func Teardown() {
	if info, err := removeProxyRule(); err != nil {
		log.Warn("%s:%s", err, info)
	}
}

func appendProxyRule() {
	dnsUDP := "iptables -t nat -A PREROUTING -d %s -p udp --dport 53 -j DNAT --to-destination :%d"
	dnsTCP := "iptables -t nat -A PREROUTING -d %s -p tcp --dport 53 -j DNAT --to-destination :%d"
	if cfg.DNS.Listen.Port != 53 {
		execCmd("/bin/bash", "-c", fmt.Sprintf(dnsUDP, cfg.DNS.Listen.IP, cfg.DNS.Listen.Port))
		execCmd("/bin/bash", "-c", fmt.Sprintf(dnsTCP, cfg.DNS.Listen.IP, cfg.DNS.Listen.Port))
	}
	execCmd("/bin/bash", "-c", "iptables -t mangle -N TRANSPARENT_PROXY")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 0.0.0.0/8 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 10.0.0.0/8 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 127.0.0.0/8 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 169.254.0.0/16 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 172.16.0.0/12 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 192.168.0.0/16 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 224.0.0.0/4 -j RETURN")
	execCmd("/bin/bash", "-c", "iptables -t mangle -A TRANSPARENT_PROXY -d 240.0.0.0/4 -j RETURN")
	proxyUDP := "iptables -t mangle -A TRANSPARENT_PROXY -p udp -j TPROXY --on-port %d --tproxy-mark %d"
	proxyTCP := "iptables -t mangle -A TRANSPARENT_PROXY -p tcp -j TPROXY --on-port %d --tproxy-mark %d"
	execCmd("/bin/bash", "-c", fmt.Sprintf(proxyUDP, cfg.Port, proxyFWMark))
	execCmd("/bin/bash", "-c", fmt.Sprintf(proxyTCP, cfg.Port, proxyFWMark))
	execCmd("/bin/bash", "-c", "iptables -t mangle -A PREROUTING -j TRANSPARENT_PROXY")
	execCmd("/bin/bash", "-c", fmt.Sprintf("ip rule add fwmark %d table %d", proxyFWMark, proxyTable))
	execCmd("/bin/bash", "-c", fmt.Sprintf("ip route add local default dev lo table %d", proxyTable))
}

func removeProxyRule() (info string, err error) {
	if info, err = runCmd("/bin/bash", "-c", "iptables-save"); err != nil || len(info) == 0 {
		return
	}
	doc := info
	beg := 6 + strings.Index(doc, "\n*nat\n")
	end := beg + strings.Index(doc[beg:], "\nCOMMIT\n")
	re := regexp.MustCompile(`--dport 53 -j DNAT`)
	for _, line := range strings.Split(doc[beg:end], "\n") {
		if re.MatchString(line) {
			if info, err = runCmd("/bin/bash", "-c", "iptables -t nat -D"+line[2:]); err != nil {
				return
			}
		}
	}
	beg = 9 + strings.Index(doc, "\n*mangle\n")
	end = beg + strings.Index(doc[beg:], "\nCOMMIT\n")
	re = regexp.MustCompile(`-j TRANSPARENT_PROXY`)
	for _, line := range strings.Split(doc[beg:end], "\n") {
		if re.MatchString(line) {
			if info, err = runCmd("/bin/bash", "-c", "iptables -t mangle -D"+line[2:]); err != nil {
				return
			}
		}
	}
	if _, err = runCmd("/bin/bash", "-c", "iptables -t mangle -F TRANSPARENT_PROXY"); err == nil {
		_, _ = runCmd("/bin/bash", "-c", "iptables -t mangle -X TRANSPARENT_PROXY")
	}
	_, _ = runCmd("/bin/bash", "-c", fmt.Sprintf("ip rule del fwmark %d table %d", proxyFWMark, proxyTable))
	_, _ = runCmd("/bin/bash", "-c", fmt.Sprintf("ip route flush table %d", proxyTable))
	return
}

func FilterUDPSrc(addr *net.UDPAddr) {
	mux.Lock()
	defer mux.Unlock()
	rule := fmt.Sprintf("TRANSPARENT_PROXY -s %s -p udp --sport %d -j RETURN", addr.IP, addr.Port)
	if _, err := runCmd("/bin/bash", "-c", "iptables -t mangle -C "+rule); err != nil {
		cmd := "iptables -t mangle -I " + rule
		if info, err := runCmd("/bin/bash", "-c", cmd); err != nil {
			log.Warn("%s:%s", err, info)
		} else {
			log.Info(cmd)
		}
	}
}

func execCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	if err := cmd.Run(); err != nil {
		log.Fatal("%s", err)
	}
}

func runCmd(name string, args ...string) (string, error) {
	buf := bytes.NewBuffer(nil)
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = buf, buf
	err := cmd.Run()
	return buf.String(), err
}
