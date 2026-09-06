# domaintest

Checks the technical configuration of a domain name and prints one compact
JSON report.

```
domaintest [-4|-6] [-t seconds] [-pretty] [-quicprobe path] [-delv path] [-dig path] <domain> [@dnsserver]
```

Like `dig`, the optional `@dnsserver` may appear anywhere on the command
line. Without it the system resolver is used.

## What it checks

1. **DNS records** with `delv` (DNSSEC-validating): A, AAAA, MX, TXT and NS
   at the apex, A and AAAA for `www.`, plus DS and DNSKEY. Every answer
   carries its trust level (`secure` / `insecure`).
2. **DNSSEC state**: `secure`, `insecure`, `island` (DNSKEY but no DS),
   `bogus` (validation fails; confirmed with `dig +cd` and the resolver's
   Extended DNS Error), `servfail`, or `unknown`.
3. **Delegation**: `dig +trace` from `a.root-servers.net` compares the NS
   set the parent zone delegates to with the NS set the zone itself serves.
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

Warnings: no A/AAAA at apex or www, no MX, no SPF in TXT, DNSSEC island,
addresses with nothing listening on 80 or 443, HTTPS without QUIC.

## Timeouts

`-t` (default 5 s) bounds every phase: all `delv` lookups together, each TCP
connect, each `quicprobe` run, and the delegation trace (which gets twice
the budget with half of it per query, so one slow root or TLD server does
not sink the whole trace). A run against a healthy domain takes well under a
second; the worst case is about twice the timeout.

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
