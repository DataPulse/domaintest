// domaintest — check the technical configuration of a domain name.
//
// Usage: domaintest [flags] <domain> [@dnsserver]
//
// Looks up A, AAAA, MX, TXT and NS for the apex and A/AAAA for www using
// delv (with DNSSEC validation), probes TCP 80/443 and QUIC on every
// address over IPv4 and IPv6, traces the delegation from the root to
// compare parent and child NS sets, and prints one JSON report.
//
// Exit codes: 0 healthy, 1 errors found in the domain, 2 usage or tool
// failure.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// Default timeouts assume a well-connected vantage point: a server that
// does not complete a TCP or QUIC handshake within two seconds is dead or
// misconfigured, and a DNS lookup that needs more than three is broken.
const (
	defaultTimeoutSec     = 3
	defaultTCPTimeoutSec  = 2
	defaultQuicTimeoutSec = 2
	usage                 = "usage: domaintest [-4|-6] [-t seconds] [-tcp-timeout seconds] [-quic-timeout seconds] [-pretty] [-quicprobe path] [-delv path] [-dig path] <domain> [@dnsserver]"
)

// config is the parsed command line.
type config struct {
	Domain        string   // A-label (punycode) form, lower case, no trailing dot
	UnicodeDomain string   // U-label form when Domain is an IDN, else ""
	Resolver      resolver // zero value means the system resolver
	Families      []string
	TimeoutSec    int
	// QuicTimeoutSec bounds each QUIC handshake separately: a host without a
	// UDP 443 listener never answers, so the general timeout would be paid
	// in full by every non-QUIC site.
	QuicTimeoutSec int
	TCPTimeoutSec  int
	Pretty         bool
	DelvPath       string
	DigPath        string
	QuicPath       string
	dnsFamily      string // family forced on delv by a literal @server address
}

func (c config) timeout() time.Duration    { return time.Duration(c.TimeoutSec) * time.Second }
func (c config) tcpTimeout() time.Duration { return time.Duration(c.TCPTimeoutSec) * time.Second }

func (c config) wantsFamily(f string) bool {
	for _, x := range c.Families {
		if x == f {
			return true
		}
	}
	return false
}

// resolver is the DNS server named with @ on the command line.
type resolver struct {
	Host string // IP literal or hostname; "" for the system resolver
	Port int    // 0 for the default port 53
}

// parseResolver accepts host, host:port, v6addr and [v6addr]:port.
func parseResolver(s string) (resolver, error) {
	if s == "" {
		return resolver{}, errors.New("empty @server")
	}
	if _, err := netip.ParseAddr(s); err == nil || !strings.Contains(s, ":") {
		return resolver{Host: s}, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return resolver{}, fmt.Errorf("invalid @server %q: use host, host:port or [v6addr]:port", s)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return resolver{}, fmt.Errorf("invalid port in @server %q", s)
	}
	return resolver{Host: host, Port: p}, nil
}

// args renders the resolver as delv/dig arguments.
func (r resolver) args() []string {
	if r.Host == "" {
		return nil
	}
	out := []string{"@" + r.Host}
	if r.Port > 0 {
		out = append(out, "-p", strconv.Itoa(r.Port))
	}
	return out
}

// String is the form shown in the report.
func (r resolver) String() string {
	switch {
	case r.Host == "":
		return "system"
	case r.Port > 0:
		return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	default:
		return r.Host
	}
}

// valueFlags take an argument, so the token after them is not positional.
var valueFlags = map[string]bool{"-t": true, "-tcp-timeout": true, "-quic-timeout": true, "-quicprobe": true, "-delv": true, "-dig": true}

// splitArgs separates argv into flag tokens, the @server and positionals so
// that, like dig, the domain and @server may appear anywhere.
func splitArgs(args []string) (flagArgs, positional []string, server string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "@"):
			if server != "" {
				return nil, nil, "", errors.New("only one @server may be given")
			}
			if server = strings.TrimPrefix(a, "@"); server == "" {
				return nil, nil, "", errors.New("empty @server")
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			flagArgs = append(flagArgs, a)
			if valueFlags[a] && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return flagArgs, positional, server, nil
}

// parseArgs builds the config from argv (without the program name).
func parseArgs(args []string) (config, error) {
	flagArgs, positional, server, err := splitArgs(args)
	if err != nil {
		return config{}, err
	}
	fs := flag.NewFlagSet("domaintest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	only4 := fs.Bool("4", false, "IPv4 only")
	only6 := fs.Bool("6", false, "IPv6 only")
	cfg := config{}
	if server != "" {
		if cfg.Resolver, err = parseResolver(server); err != nil {
			return config{}, err
		}
	}
	fs.IntVar(&cfg.TimeoutSec, "t", defaultTimeoutSec, "per-probe timeout in seconds")
	fs.IntVar(&cfg.QuicTimeoutSec, "quic-timeout", defaultQuicTimeoutSec, "QUIC handshake timeout in seconds")
	fs.IntVar(&cfg.TCPTimeoutSec, "tcp-timeout", defaultTCPTimeoutSec, "TCP connect timeout in seconds")
	fs.BoolVar(&cfg.Pretty, "pretty", false, "indent the JSON output")
	fs.StringVar(&cfg.QuicPath, "quicprobe", "", "path to the quicprobe binary")
	fs.StringVar(&cfg.DelvPath, "delv", "", "path to delv")
	fs.StringVar(&cfg.DigPath, "dig", "", "path to dig")
	if err := fs.Parse(flagArgs); err != nil {
		return config{}, err
	}
	if len(positional) != 1 {
		return config{}, errors.New("exactly one domain is required")
	}
	if cfg.TimeoutSec <= 0 {
		return config{}, errors.New("-t must be a positive number of seconds")
	}
	if cfg.QuicTimeoutSec <= 0 {
		return config{}, errors.New("-quic-timeout must be a positive number of seconds")
	}
	if cfg.TCPTimeoutSec <= 0 {
		return config{}, errors.New("-tcp-timeout must be a positive number of seconds")
	}
	cfg.Domain, cfg.UnicodeDomain, err = normalizeDomain(positional[0])
	if err != nil {
		return config{}, err
	}
	cfg.Families = chooseFamilies(*only4, *only6)
	cfg.dnsFamily = serverFamily(cfg.Resolver.Host)
	return cfg, nil
}

func chooseFamilies(only4, only6 bool) []string {
	switch {
	case only4 && !only6:
		return []string{familyIPv4}
	case only6 && !only4:
		return []string{familyIPv6}
	default:
		return []string{familyIPv4, familyIPv6}
	}
}

// serverFamily returns the family a literal @server address pins delv to,
// or "" for a hostname or the system resolver.
func serverFamily(server string) string {
	ip, err := netip.ParseAddr(server)
	if err != nil {
		return ""
	}
	if ip.Unmap().Is4() {
		return familyIPv4
	}
	return familyIPv6
}

// idnaProfile applies IDNA 2008 lookup mapping and validation but, unlike
// idna.Lookup, tolerates underscores so that names such as _dmarc.example
// can be checked. Other non-hostname ASCII is still rejected by validLabel.
var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.BidiRule())

// normalizeDomain accepts a domain in U-label (münchen.de) or A-label
// (xn--mnchen-3ya.de) form, in any case and with or without a trailing dot,
// and returns the canonical A-label form plus the U-label form when the two
// differ. IDNA 2008 lookup rules are applied, so malformed punycode and
// disallowed code points are rejected.
func normalizeDomain(input string) (ascii, unicode string, err error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(input), ".")
	if trimmed == "" {
		return "", "", fmt.Errorf("invalid domain %q", input)
	}
	ascii, err = idnaProfile.ToASCII(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("invalid domain %q: %v", input, err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", "", fmt.Errorf("invalid domain %q: longer than 253 octets", input)
	}
	for _, label := range strings.Split(ascii, ".") {
		if !validLabel(label) {
			return "", "", fmt.Errorf("invalid domain label %q in %q", label, input)
		}
	}
	unicode, err = idnaProfile.ToUnicode(ascii)
	if err != nil || unicode == ascii {
		unicode = ""
	}
	return ascii, unicode, nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	return strings.IndexFunc(l, func(c rune) bool { return !labelChar(c) }) < 0
}

// labelChar reports whether c may appear in a (lower-cased) hostname label.
func labelChar(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	default:
		return c == '-' || c == '_'
	}
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain is main without os.Exit so tests can drive it.
func realMain(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "domaintest: %v\n%s\n", err, usage)
		return 2
	}
	if err := resolveTools(&cfg); err != nil {
		fmt.Fprintf(stderr, "domaintest: %v\n", err)
		return 2
	}
	rep := run(context.Background(), cfg, execRunner{}, &netDialer{})
	if err := writeReport(stdout, rep, cfg.Pretty); err != nil {
		fmt.Fprintf(stderr, "domaintest: %v\n", err)
		return 2
	}
	if rep.OK {
		return 0
	}
	return 1
}

func resolveTools(cfg *config) error {
	var err error
	if cfg.DelvPath, err = requireTool(cfg.DelvPath, "delv"); err != nil {
		return err
	}
	if cfg.DigPath, err = requireTool(cfg.DigPath, "dig"); err != nil {
		return err
	}
	cfg.QuicPath, err = findQuicprobe(cfg.QuicPath)
	return err
}

func writeReport(w io.Writer, rep *Report, pretty bool) error {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(rep)
}
