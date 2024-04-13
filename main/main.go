package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"lib.za/log"

	"proxy-router/adapter"
	"proxy-router/cfg"
	"proxy-router/component/iptable"
	"proxy-router/dns"
	"proxy-router/dns/iquery"
	"proxy-router/utils"
)

func main() {
	log.SetFlags(log.Flags() | log.LFile)
	go func() {
		err := http.ListenAndServe(":6060", nil)
		log.Debug("%s", err)
	}()

	pf := utils.PidFile{Name: filepath.Join(cfg.WorkDir, "server.pid")}
	if err := pf.Lock(); err != nil {
		log.Fatal("%s", err)
	}
	defer pf.Unlock()
	iptable.Setup()
	iquery.Load()
	dns.Start()
	adapter.Start()
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	for s := range sig {
		if s == syscall.SIGUSR1 {
			_ = log.SetLogfile(filepath.Join(cfg.WorkDir, "server.log"))
		} else {
			break
		}
	}
	dns.Stop()
	adapter.Stop()
	iquery.Save()
	cfg.SaveProfile()
	iptable.Teardown()
}
