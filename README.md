# domaintest

Checks the technical configuration of a domain name and prints one compact
JSON report.

```
domaintest [-4|-6] [-t seconds] [-tcp-timeout seconds] [-quic-timeout seconds] [-pretty] [-quicprobe path] [-delv path] [-dig path] <domain> [@dnsserver[:port]]
```

Like `dig`, the optional `@dnsserver` may appear anywhere on the command
line. Without it the system resolver is used. A port may be appended
(`@127.0.0.1:5353`, `@[::1]:5353`); without one the default 53 applies.

The domain may be given as a U-label (`münchen.de`) or an A-label
(`xn--mnchen-3ya.de`), in any case, with or without a trailing dot. IDNA
2008 lookup rules apply. The report's `domain` is always the A-label and
`unicode_domain` carries the U-label form when the two differ.

## What it checks

1. **DNS records** with `delv` (DNSSEC-validating): A, AAAA, MX, TXT and NS
   at the apex, A and AAAA for `www.`, plus DS and DNSKEY. Every answer
   carries its trust level (`secure` / `insecure`).
2. **DNSSEC state**: `secure`, `insecure`, `island` (DNSKEY but no DS),
   `bogus` (validation fails; confirmed with `dig +cd` and the resolver's
   Extended DNS Error), `servfail`, or `unknown`.
3. **Delegation**: `dig +trace` from `a.root-servers.net` compares the NS
   set the parent zone delegates to with the NS set the zone itself serves.
   Status `same_servers` means the parent zone's servers also host the
   child (common for a registry's own domain such as nic.cz) and answered
   authoritatively, so the delegation cannot be observed separately.
   `child_no_ns` is a lame zone: the delegated servers answer with the
   apex SOA but publish no NS RRset. `not_a_zone` means the name is a host
   inside a zone: its NS query answers with no records while it has some
   other record (A, AAAA, MX or TXT, so `_dmarc.example.com` counts) or a
   negative answer carried the SOA of a zone above it, and the parent does
   not delegate it. The delegation trace and the DS/DNSKEY zone checks are
   then skipped, `dnssec.state` is taken from the validation status of the
   answers, and `not_a_zone` / `enclosing_zone` appear in the report.
4. **Web reachability**: TCP connect to ports 80 and 443 on every A and
   AAAA address of the apex and `www.`, deduplicated when both names share
   addresses. Port 25 is deliberately not probed.
5. **QUIC / HTTP3** via the sibling `quicprobe` tool. This is sampled:
   one probe per name and address family, on the first address of that
   family, so only that address carries a `quic` object and the
   "QUIC/h3 works on another probed address" warning can only compare
   IPv4 with IPv6, or apex with www.
6. **Resolver reachability** over IPv4 and IPv6 (a root NS query per
   family). A family is `skipped` when the resolver has no address in it:
   with `@127.0.0.1:8053` or any IPv4 literal, `ipv6` is always `skipped`
   even though `families` still lists it for the TCP and QUIC probes. That
   is expected, not a defect.

Steps 4 and 5 run over both IPv4 and IPv6 unless `-4` or `-6` is given.
DNS record data is fetched once; a literal `@server` address fixes the DNS
transport family.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no errors found |
| 1 | the report contains errors (`"ok": false`) |
| 2 | usage error, or `delv`, `dig` or `quicprobe` not found |

## Report

Single-line JSON on stdout (`-pretty` indents). Top-level keys: `domain`,
`unicode_domain` (IDN only), `resolver`, `families`, `timeout_sec`,
`tcp_timeout_sec`, `quic_timeout_sec`, `not_a_zone` and `enclosing_zone`
(hosts only), `dns`, `dnssec`, `delegation`, `web`, `errors`, `warnings`,
`ok`, `elapsed_ms`.

`web` is an empty object when the name has no usable addresses (no
A/AAAA, NXDOMAIN, bogus zone): callers must not assume `web.apex` exists.
Per-lookup objects carry `retries: 1` when the first delv attempt timed
out and the retry answered.

Errors (set `ok` to false): apex NXDOMAIN, missing NS, DNSSEC bogus or
SERVFAIL, delegation mismatch / not delegated / no child answer / lame
zone, lookups that failed or timed out, resolver unreachable over an
enabled family. A bogus zone yields one DNSSEC error; the per-lookup
failures it causes are folded into it rather than listed one by one.

Warnings: no A/AAAA at apex or www, `www` name does not exist, no MX, a
null MX (RFC 7505, accepts no mail), no SPF in TXT, name is not a zone
apex, DNSSEC island or unknown, addresses with nothing listening on 80 or
443, addresses where HTTP answers but HTTPS does not, and QUIC working on
one probed address of a host but not another. A host with no QUIC at all
is not flagged; the per-address result is in the `web` section.

## Timeouts

Defaults assume a well-connected vantage point such as an AWS host: a
server that cannot complete a handshake in two seconds is dead or
misconfigured.

`-t` (default 3 s) bounds all `delv` lookups together and the delegation
trace (which gets twice the budget with half of it per query, so one slow
root or TLD server does not sink the whole trace).

`-tcp-timeout` (default 2 s) bounds each TCP connect to 80 and 443.

`-quic-timeout` (default 2 s) bounds each QUIC handshake. A host without a
UDP 443 listener never answers, so every non-QUIC site would otherwise pay
the full `-t`; servers that do speak QUIC, or actively refuse it, answer
within tens of milliseconds.

A `delv` lookup that times out in the first half of its budget is retried
once (`"retries": 1` in the record), so one dropped UDP query does not cost
the whole run. A run against a healthy domain takes well under a second
when QUIC answers and about `-quic-timeout` when it does not.

## Requirements

- `delv` and `dig` (BIND 9.18 or later, `+yaml` support) on `PATH`.
- `quicprobe` on `PATH`, at `../quicprobe/quicprobe` next to the binary or
  the working directory, or given with `-quicprobe`. It must support the
  `-ip` and `-t` flags.
- Go 1.27.1 (the `go` directive in `go.mod`; an older `go` downloads it).

## Tests

```
go test -short ./...   # unit tests, fixtures captured from real tool output
go test ./...          # also runs the network integration tests
```
