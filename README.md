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
   inside a zone (it has addresses but no NS), so the delegation and
   DNSSEC zone checks are skipped and `not_a_zone` / `enclosing_zone`
   appear in the report.
4. **Web reachability**: TCP connect to ports 80 and 443 on every A and
   AAAA address of the apex and `www.`, deduplicated when both names share
   addresses. Port 25 is deliberately not probed.
5. **QUIC / HTTP3** via the sibling `quicprobe` tool, once per address
   family and name, on the first address of that family.
6. **Resolver reachability** over IPv4 and IPv6 (a root NS query per
   family). Skipped for a family the resolver has no address for.

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
`resolver`, `families`, `timeout_sec`, `dns`, `dnssec`, `delegation`,
`web`, `errors`, `warnings`, `ok`, `elapsed_ms`.

Errors (set `ok` to false): apex NXDOMAIN, missing NS, DNSSEC bogus or
SERVFAIL, delegation mismatch / not delegated / no child answer, lookups
that failed or timed out, resolver unreachable over an enabled family.

Warnings: no A/AAAA at apex or www, no MX, a null MX (RFC 7505, accepts
no mail), no SPF in TXT, name is not a zone apex, DNSSEC island,
addresses with nothing listening on 80 or 443, and QUIC working on some
addresses of a host but not others. A host with no QUIC at all is not
flagged; the per-address result is in the `web` section.

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
