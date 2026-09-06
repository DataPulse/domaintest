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
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	defaultTimeoutSec = 5
	usage             = "usage: domaintest [-4|-6] [-t seconds] [-pretty] [-quicprobe path] [-delv path] [-dig path] <domain> [@dnsserver]"
)

// config is the parsed command line.
type config struct {
	Domain     string
	Server     string // "" for the system resolver
	Families   []string
	TimeoutSec int
	Pretty     bool
	DelvPath   string
	DigPath    string
	QuicPath   string
	dnsFamily  string // family forced on delv by a literal @server address
}

func (c config) timeout() time.Duration { return time.Duration(c.TimeoutSec) * time.Second }

func (c config) wantsFamily(f string) bool {
	for _, x := range c.Families {
		if x == f {
			return true
		}
	}
	return false
}

// valueFlags take an argument, so the token after them is not positional.
var valueFlags = map[string]bool{"-t": true, "-quicprobe": true, "-delv": true, "-dig": true}

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
			server = strings.TrimPrefix(a, "@")
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
	cfg := config{Server: server}
	fs.IntVar(&cfg.TimeoutSec, "t", defaultTimeoutSec, "per-probe timeout in seconds")
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
	cfg.Domain, err = normalizeDomain(positional[0])
	if err != nil {
		return config{}, err
	}
	cfg.Families = chooseFamilies(*only4, *only6)
	cfg.dnsFamily = serverFamily(server)
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

// normalizeDomain lower-cases, strips the trailing dot and applies basic
// hostname label rules.
func normalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if d == "" || len(d) > 253 {
		return "", fmt.Errorf("invalid domain %q", d)
	}
	for _, label := range strings.Split(d, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid domain label %q in %q", label, d)
		}
	}
	return d, nil
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
