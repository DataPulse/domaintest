package main

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// netDialer is the production dialer.
type netDialer struct{ net.Dialer }

// dnsResults collects every delv lookup for one run.
type dnsResults struct {
	apex   map[string]Lookup
	www    map[string]Lookup
	ds     Lookup
	dnskey Lookup
	reach  map[string]string
}

// run performs every check for cfg and returns the finished report.
func run(ctx context.Context, cfg config, r Runner, d dialer) *Report {
	start := time.Now()
	rep := &Report{
		Domain:     cfg.Domain,
		Resolver:   resolverName(cfg.Server),
		Families:   cfg.Families,
		TimeoutSec: cfg.TimeoutSec,
	}

	var dns dnsResults
	parallel(
		func() { rep.Delegation = runTrace(ctx, cfg, r) },
		func() { dns = gatherDNS(ctx, cfg, r) },
	)

	rep.DNS = DNSSection{Apex: dns.apex, WWW: dns.www, ResolverReachable: dns.reach}
	probeCtx, cancel := context.WithTimeout(ctx, cfg.timeout()+time.Second)
	defer cancel()
	rep.DNSSEC = classifyDNSSEC(dns.ds, dns.dnskey, dns.apex,
		newBogusProbe(probeCtx, r, cfg.DigPath, cfg.Server, cfg.TimeoutSec))
	rep.Web = probeWeb(probeCtx, cfg, r, d, dns)

	buildFindings(rep)
	rep.ElapsedMs = time.Since(start).Milliseconds()
	return rep
}

func resolverName(server string) string {
	if server == "" {
		return "system"
	}
	return server
}

// parallel runs fns concurrently and waits for all of them.
func parallel(fns ...func()) {
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			fn()
		}(fn)
	}
	wg.Wait()
}

// runTrace runs the delegation trace under twice the configured timeout:
// it is a chain of about five sequential queries, each already limited by
// dig's own +time.
func runTrace(ctx context.Context, cfg config, r Runner) Delegation {
	tctx, cancel := context.WithTimeout(ctx, 2*cfg.timeout())
	defer cancel()
	family := familyIPv4
	if !cfg.wantsFamily(familyIPv4) {
		family = familyIPv6
	}
	return traceDelegation(tctx, r, cfg.DigPath, family, cfg.TimeoutSec, cfg.Domain)
}

// gatherDNS runs all delv lookups in parallel under one deadline.
func gatherDNS(ctx context.Context, cfg config, r Runner) dnsResults {
	dctx, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	res := dnsResults{
		apex:  make(map[string]Lookup, len(apexTypes)),
		www:   make(map[string]Lookup, len(wwwTypes)),
		reach: make(map[string]string, len(cfg.Families)),
	}
	var mu sync.Mutex
	look := func(name, qtype string) Lookup {
		return delvLookup(dctx, r, cfg.DelvPath, cfg.Server, "", name, qtype)
	}
	var tasks []func()
	for _, t := range apexTypes {
		tasks = append(tasks, func() { store(&mu, res.apex, t, look(cfg.Domain, t)) })
	}
	for _, t := range wwwTypes {
		tasks = append(tasks, func() { store(&mu, res.www, t, look("www."+cfg.Domain, t)) })
	}
	tasks = append(tasks,
		func() { l := look(cfg.Domain, "DS"); mu.Lock(); res.ds = l; mu.Unlock() },
		func() { l := look(cfg.Domain, "DNSKEY"); mu.Lock(); res.dnskey = l; mu.Unlock() },
	)
	for _, fam := range cfg.Families {
		tasks = append(tasks, func() {
			store(&mu, res.reach, fam, checkReachability(dctx, cfg, r, fam))
		})
	}
	parallel(tasks...)
	return res
}

func store[V any](mu *sync.Mutex, m map[string]V, k string, v V) {
	mu.Lock()
	defer mu.Unlock()
	m[k] = v
}

// reachabilityQuery is the name queried to test the resolver: the root NS
// set, which every resolver can answer regardless of the domain's health.
const reachabilityQuery = "."

// checkReachability asks the resolver for the root NS set over a single
// transport family. It is skipped when the resolver has no address of
// that family.
func checkReachability(ctx context.Context, cfg config, r Runner, family string) string {
	if !resolverSupports(cfg, family) {
		return ReachSkipped
	}
	l := delvLookup(ctx, r, cfg.DelvPath, cfg.Server, family, reachabilityQuery, "NS")
	if l.Answered() {
		return ReachYes
	}
	return ReachNo
}

// resolverSupports reports whether DNS over family makes sense: a literal
// @server pins the family; the system resolver is checked against the
// nameserver lines of /etc/resolv.conf; a hostname server is assumed to.
func resolverSupports(cfg config, family string) bool {
	if cfg.dnsFamily != "" {
		return cfg.dnsFamily == family
	}
	if cfg.Server != "" {
		return true
	}
	fams := resolvConfFamilies(resolvConfPath)
	return len(fams) == 0 || fams[family]
}

var resolvConfPath = "/etc/resolv.conf"

// resolvConfFamilies returns the address families of the nameservers in a
// resolv.conf file. An unreadable file yields an empty map.
func resolvConfFamilies(path string) map[string]bool {
	fams := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return fams
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if fam := serverFamily(strings.Split(fields[1], "%")[0]); fam != "" {
			fams[fam] = true
		}
	}
	return fams
}

// probeWeb runs TCP and QUIC probes for apex and www, collapsing www into
// apex when both resolve to the same addresses.
func probeWeb(ctx context.Context, cfg config, r Runner, d dialer, dns dnsResults) WebSection {
	apexAddrs := wantedAddrs(cfg, dns.apex["A"], dns.apex["AAAA"])
	wwwAddrs := wantedAddrs(cfg, dns.www["A"], dns.www["AAAA"])
	same := len(apexAddrs) > 0 && sameAddressSet(apexAddrs, wwwAddrs)

	var ports map[portKey]PortState
	var apexQUIC, wwwQUIC map[string]*QUICResult
	tasks := []func(){
		func() { ports = probePorts(ctx, d, append(apexAddrs, wwwAddrs...), webPorts, cfg.timeout()) },
		func() { apexQUIC = quicPerFamily(ctx, cfg, r, cfg.Domain, apexAddrs) },
	}
	if !same {
		tasks = append(tasks, func() { wwwQUIC = quicPerFamily(ctx, cfg, r, "www."+cfg.Domain, wwwAddrs) })
	}
	parallel(tasks...)

	web := WebSection{Apex: hostWeb(apexAddrs, ports, apexQUIC)}
	if same {
		web.WWW = &HostWeb{SameAsApex: true}
	} else {
		web.WWW = hostWeb(wwwAddrs, ports, wwwQUIC)
	}
	return web
}

// wantedAddrs returns the addresses from A/AAAA lookups that belong to an
// enabled family.
func wantedAddrs(cfg config, lookups ...Lookup) []netip.Addr {
	var out []netip.Addr
	for _, l := range lookups {
		for _, ip := range l.Addrs() {
			if cfg.wantsFamily(familyOf(ip)) {
				out = append(out, ip)
			}
		}
	}
	return out
}

func familyOf(ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return familyIPv4
	}
	return familyIPv6
}

// quicPerFamily probes QUIC once per family, on the first address of that
// family, keyed by the address string.
func quicPerFamily(ctx context.Context, cfg config, r Runner, host string, addrs []netip.Addr) map[string]*QUICResult {
	first := map[string]netip.Addr{}
	for _, ip := range addrs {
		if _, ok := first[familyOf(ip)]; !ok {
			first[familyOf(ip)] = ip
		}
	}
	out := map[string]*QUICResult{}
	var mu sync.Mutex
	var tasks []func()
	for _, ip := range first {
		tasks = append(tasks, func() {
			q := probeQUIC(ctx, r, cfg.QuicPath, host, ip, cfg.TimeoutSec)
			mu.Lock()
			out[ip.String()] = &q
			mu.Unlock()
		})
	}
	parallel(tasks...)
	return out
}

// hostWeb assembles the per-address results for one hostname.
func hostWeb(addrs []netip.Addr, ports map[portKey]PortState, quic map[string]*QUICResult) *HostWeb {
	if len(addrs) == 0 {
		return nil
	}
	h := &HostWeb{}
	seen := map[netip.Addr]bool{}
	for _, ip := range addrs {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		a := AddrWeb{
			IP:    ip.String(),
			HTTP:  ports[portKey{IP: ip, Port: 80}],
			HTTPS: ports[portKey{IP: ip, Port: 443}],
			QUIC:  quic[ip.String()],
		}
		if ip.Is4() {
			h.IPv4 = append(h.IPv4, a)
		} else {
			h.IPv6 = append(h.IPv6, a)
		}
	}
	return h
}
