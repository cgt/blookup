package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
)

var dnsbl = []string{
	"all.s5h.net",
	"b.barracudacentral.org",
	"bl.blocklist.de",
	"bl.mailspike.net",
	"bl.spamcannibal.org",
	"bl.spamcop.net",
	"bl.spameatingmonkey.net",
	"db.wpbl.info",
	"dnsbl-1.uceprotect.net",
	"dnsbl.cobion.com",
	"dnsbl.inps.de",
	"dnsbl.sorbs.net",
	"hostkarma.junkemailfilter.com",
	"ix.dnsbl.manitu.net",
	"psbl.surriel.com",
	"srnblack.surgate.net",
	"stabl.rbl.webiron.net",
	"truncate.gbudb.net",
	"zen.spamhaus.org",
}

var dnswl = []string{
	"list.dnswl.org",
	"swl.spamhaus.org",
	"wl.mailspike.net",
}

type ListType string

const (
	TWhitelist = "WL"
	TBlacklist = "BL"
)

type Listing struct {
	Type     ListType
	Name     string
	Listings []net.IP
}

func lookup(ip net.IP, blacklist string) ([]net.IP, error) {
	return net.LookupIP(reverseaddr(ip) + "." + blacklist)
}

func main() {
	var (
		flagNoPtr bool
	)
	flag.BoolVar(&flagNoPtr, "noptr", false, "disables PTR lookup")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s IP\n", os.Args[0])
		os.Exit(1)
	}

	ip := net.ParseIP(flag.Arg(0))
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Invalid IP: %s\n", flag.Arg(0))
		os.Exit(1)
	}

	var wg sync.WaitGroup
	listings := make(chan Listing)

	for _, bl := range dnsbl {
		wg.Add(1)
		go func(blacklist string) {
			ips, _ := lookup(ip, blacklist)
			listings <- Listing{TBlacklist, blacklist, ips}
			wg.Done()
		}(bl)
	}

	for _, wl := range dnswl {
		wg.Add(1)
		go func(whitelist string) {
			ips, _ := lookup(ip, whitelist)
			listings <- Listing{TWhitelist, whitelist, ips}
			wg.Done()
		}(wl)
	}

	go func(noptr bool) {
		if !noptr {
			ptr, err := net.LookupAddr(flag.Arg(0))
			if err == nil {
				fmt.Println("PTR", ptr[0])
			} else {
				fmt.Println(err)
			}
		}
		var buf bytes.Buffer
		for l := range listings {
			buf.Reset()
			for _, x := range l.Listings {
				buf.WriteString(string(l.Type))
				buf.WriteByte(' ')
				buf.WriteString(l.Name)
				buf.WriteByte(' ')
				buf.WriteString(x.String())
				buf.WriteByte('\n')
			}
			fmt.Print(buf.String())
		}
	}(flagNoPtr)
	wg.Wait()
}
