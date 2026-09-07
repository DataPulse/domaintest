# domaintest

Checks the technical configuration of a domain name and prints one compact
JSON report.

```
domaintest [-4|-6] [-t seconds] [-tcp-timeout seconds] [-quic-timeout seconds] [-no-hsts-preload] [-hsts-cache path] [-pretty] [-quicprobe path] [-delv path] [-dig path] <domain> [@dnsserver[:port]]
domaintest -warm-hsts-cache
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
   carries its trust level (`secure` / `insecure`). Apex or www addresses
   inside reserved ranges (RFC 1918, loopback, link-local, CGNAT,
   documentation, multicast, ULA) are an error and are not probed
   (`reserved_addresses`, ports `skipped`).
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
4. **Nameserver audit** (`nameservers`): every NS name is resolved (a
   CNAME or an unresolvable name is an error) and every address is asked
   for the zone SOA non-recursively over UDP, over TCP and with EDNS/DNSSEC
   in one `dig` run: not authoritative or unreachable is an error, no TCP
   or no EDNS a warning, SOA serial drift between servers a warning. Fewer
   than two nameservers is an error; all IPv4 addresses in one /24 or all
   IPv6 in one /48 is a warning. For in-bailiwick nameservers the parent's
   glue is compared with the zone's own addresses (missing glue is an
   error, a differing address a warning). No zone transfer is ever
   requested.
5. **Web reachability**: TCP connect to ports 80 and 443 on every A and
   AAAA address of the apex and `www.` (probed separately, since the TLS
   name and Host header differ even when addresses are shared). Port 25 is
   deliberately not probed.
6. **TLS on 443**, on every address that answered (`tls`): the served
   chain is classified as `valid`, `expired`, `not_yet_valid`,
   `hostname_mismatch`, `self_signed`, `incomplete_chain` (the missing
   intermediate is fetched via the certificate's AIA URL to prove it),
   `untrusted_root`, `invalid` or `handshake_failed`; anything but `valid`
   is an error. The certificate's subject, issuer, validity, days
   remaining (warning under 30, with sharper wording under 14 and 7), SANs,
   whether it covers the apex and www, key type and SHA-256 fingerprint are
   reported. A valid certificate on one name that does not cover the other
   resolving name is a warning, as is a host whose addresses serve
   different certificates. Two extra handshakes test whether TLS 1.0 and
   TLS 1.1 are still accepted (warnings), and negotiating less than TLS 1.3
   is a warning. Only `http/1.1` is offered via ALPN so that the HTTP
   request below can reuse the connection.
7. **HTTP** (`http` on 80, `https` on 443, per address): one `GET /` with
   the proper Host header; status, Location and Server header are
   recorded, plus the parsed `Strict-Transport-Security` header
   (`max_age`, `include_subdomains`, `preload`). Every address answering
   5xx on a port is an error, some of them a warning, every address 4xx a
   warning. Port 80 serving content instead of redirecting to https is a
   warning, as is an HSTS max-age under 180 days. HSTS absence is a fact,
   not a warning. `hsts_preload` says whether browsers enforce HSTS for the
   name regardless of the header, read from Chromium's preload list (see
   **HSTS preload list** below): `preloaded`, `absent` or `unknown` (the
   list could not be obtained; `hsts_preload_error` says why, with resolver
   addresses removed). When an ancestor entry rather than the name itself
   makes it preloaded, `hsts_preload_covered_by` names that ancestor, so a
   name under `app`, `bank`, `dev` or `page` reads preloaded with the TLD
   as the cover. A preloaded domain whose served header no longer meets the
   preload bar (max-age of a year, includeSubDomains, preload), or a header
   that carries `preload` without meeting it, is a warning.
   `-no-hsts-preload` skips the check entirely.
8. **Redirect chains** (`redirects`, per name and address family): from
   `http://<name>/` on the first address of the family, following
   Location headers up to three hops while the target stays apex or www.
   A loop or an over-long chain is an error, a chain that breaks after it
   started or ends in 4xx/5xx a warning, an external target is recorded
   as `external` and not followed. A chain is a property of the name, so
   it is followed once per family, unlike the per-address probes above.
9. **QUIC / HTTP3** via the sibling `quicprobe` tool, on every address of
   both names, so every address carries a `quic` object and the "QUIC/h3
   works on another probed address" warning means what it says.
10. **Mail** (`mail`, zone apexes only; absent for a host inside a zone,
    like `nameservers`, since mail policy lives at the zone): DMARC at
    `_dmarc` (missing or `p=none` warn,
    multiple or unparsable records error, `pct` below 100 warns); SPF is
    evaluated, not just found: include/redirect chains are followed and
    DNS-querying terms counted (more than 10 is a permerror and an error,
    as are multiple records, `+all` and unknown mechanisms; `?all`, `ptr`,
    a missing `all`, more than two void lookups and includes without SPF
    warn); every MX target must be a resolvable hostname that is not a
    CNAME or IP literal (errors); DKIM is probed at the selectors
    `google, selector1, selector2, default, k1, s1, mail, dkim` (found
    selectors are reported, a revoked empty key warns, none found is a
    fact since selectors cannot be enumerated); MTA-STS `_mta-sts` record
    and, when present, the policy at
    `https://mta-sts.<domain>/.well-known/mta-sts.txt` fetched with full
    certificate verification, its host resolved through the tool's own
    validating lookups rather than the system resolver, and compared with
    the MX set (problems are errors in `enforce` mode, warnings otherwise);
    TLS-RPT presence. A null MX is reported as "accepts no mail". No SMTP
    connection is made. No finding ever names the resolver used.
11. **CAA** (`caa`): records at the apex and www (www falls back to the
    apex records when it has none, as RFC 8659 climbs) are compared per
    host with the issuer of the certificate that host actually served,
    using a table of CA organisations to CAA identifiers. `caa.hosts.apex`
    and `caa.hosts.www` each carry `records`, `issuer`, `permitted` and
    `note`; the top-level `issuer`, `permitted` and `note` mirror the apex
    verdict. `permitted` is true when there are no CAA records (any CA may
    issue) and absent only when nothing could be judged: no certificate
    observed, or an issuer not in the table (the note says which). A CA
    the records forbid is an error per host.
12. **DANE / TLSA** (`tlsa`): `_443._tcp.` records for apex and www are
    matched against every address's served chain per usage, selector and
    matching type. No match anywhere is an error; records in an unsigned
    zone are a warning because DANE clients ignore them. `signed` says
    whether the TLSA answers, positive or negative, were DNSSEC-validated:
    in a signed zone the denial of a missing TLSA set is itself signed, so
    `signed` is true there even with `result: none`.
13. **Wildcard** (`wildcard`): a random label under the domain is looked
    up; if it answers, the zone has a wildcard, and when www resolves to
    exactly the wildcard's addresses the report says `www_via_wildcard`
    (and www carries `via_wildcard`) with a warning.
14. **Resolver reachability** over IPv4 and IPv6 (a root NS query per
    family). A family whose transport the resolver cannot use reads
    `skipped: resolver has no ipv6 address` (or ipv4): with
    `@127.0.0.1:8053` or any IPv4 literal, `ipv6` is always skipped even
    though `families` still lists it for the TCP and QUIC probes. That is
    expected, not a defect; key on the `skipped` prefix.

Steps 5 to 9 run over both IPv4 and IPv6 unless `-4` or `-6` is given.
DNS record data is fetched once; a literal `@server` address fixes the DNS
transport family. Every DNS lookup goes through `delv`, so all answers are
independently DNSSEC-validated.

## HSTS preload list

The preload answer comes from Chromium's `transport_security_state_static.json`,
not from a per-domain API call, so **the network is touched at most once per
host**. The list is fetched once (about 1.1 MB on the wire, gzipped by the
transport), reduced to the two fields a lookup needs and cached as roughly
1.65 MB of TSV. Every later run on that host, for any domain, reads the
cache.

- **Path**: `-hsts-cache`, defaulting to
  `<user cache dir>/domaintest/hsts-preload.tsv`, i.e. `$XDG_CACHE_HOME` or
  `$HOME/.cache`. `-hsts-cache -` disables caching and fetches every run.
- **Lifetime**: none. There is no expiry, because the intended deployment
  replaces its hosts every few hours; the cache dies with the host. Delete
  the file to force a refresh.
- **Concurrency**: population is serialised with an exclusive `flock` on
  `/run/lock/domaintest-hsts.lock`, falling back to `<cache>.lock` when that
  directory is missing or unwritable, as in a container. Parallel runs on a
  cold host therefore cause exactly one download.
- **Transient failures**: a 5xx from googlesource is retried up to three
  times with a short backoff, still inside the caller's budget, because
  bursts of requests do occasionally get a 503.
- **Cold start never delays a run**: the wait for the lock and the fetch
  both sit inside the probe budget and run concurrently with the web, mail
  and nameserver checks, so the worst case is unchanged and a contended cold
  start costs that run its preload value (`unknown`), nothing more.
- **Warm at start**: `domaintest -warm-hsts-cache` populates the cache and
  exits, taking no domain, with its own 60 s budget. It prints the cache and
  lock paths to stderr and exits 2 with the reason if it fails. Run it once
  when a machine or container starts and no later run pays for a cold cache.
- **Semantics**: the list records enforcement, so there is no equivalent of
  the submission states `pending` and `rejected` that hstspreload.org
  reports; such domains read `absent`, which is what browsers do.

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
(hosts only), `dns`, `dnssec`, `delegation`, `web`, `mail`,
`nameservers` (zones only), `caa`, `tlsa`, `wildcard`,
`reserved_addresses` (when any), `hsts_preload`,
`hsts_preload_covered_by` and `hsts_preload_error` (unless disabled),
`errors`, `warnings`, `ok`, `elapsed_ms`.

Each address entry under `web.apex` / `web.www` (`ipv4[]`, `ipv6[]`) has
`ip`, `80`, `443` (open / refused / timeout / unreachable / error /
skipped), `http` and `https` (status, location, server, hsts, error),
`tls` (chain, version, alpn, cipher, tls10, tls11, cert, chain_length,
error), `tlsa` (match / mismatch / none, only when TLSA records exist) and
`quic` (every address). Each host has `same_as_apex`, `via_wildcard`,
`redirects` (per family: hops, final_url, external, loop, error) and
`cert_consistent`.

`web` is an empty object when the name has no usable addresses (no
A/AAAA, NXDOMAIN, bogus zone): callers must not assume `web.apex` exists.
`mail` and `nameservers` are absent for a name that is not a zone apex.

Conventions inside the new sections: arrays are always present (empty
rather than null), booleans are always present, strings are omitted when
empty, and an object is omitted only when the whole check did not apply
(`glue` when the parent could not be asked, `tls` when 443 did not
answer, `quic` when quicprobe was not run).
Per-lookup objects carry `retries: 1` when the first delv attempt timed
out and the retry answered.

Errors (set `ok` to false): apex NXDOMAIN, missing NS, DNSSEC bogus or
SERVFAIL, delegation mismatch / not delegated / no child answer / lame
zone, lookups that failed or timed out, resolver unreachable over an
enabled family, reserved addresses in DNS, any certificate chain problem,
every address 5xx on a port, redirect loops or over-long chains, DMARC
records that are multiple or unparsable, SPF permerrors (over the lookup
limit, multiple records), `+all`, unknown SPF mechanisms, MX targets that
are CNAMEs, IP literals or unresolvable, MTA-STS problems in enforce mode,
nameservers that are CNAMEs, unresolvable, unreachable or not
authoritative, fewer than two nameservers, missing glue, a certificate
issuer the CAA records forbid, and TLSA records matching no served
certificate. A bogus zone yields one DNSSEC error; the per-lookup failures
it causes are folded into it rather than listed one by one.

Warnings: no A/AAAA at apex or www, `www` name does not exist, no MX, a
null MX (RFC 7505, accepts no mail), no SPF in TXT, name is not a zone
apex, DNSSEC island or unknown, addresses with nothing listening on 80 or
443, addresses where HTTP answers but HTTPS does not, QUIC working on one
probed address of a host but not another, certificates expiring within 30
days, a certificate not covering the sibling name, different certificates
across a host's addresses, TLS 1.0 or 1.1 accepted, no TLS 1.3, some
addresses 5xx or all 4xx, clear-text HTTP without redirect, HSTS max-age
under 180 days, broken redirect chains, missing DMARC or `p=none` or
`pct<100`, SPF `?all` / `ptr` / missing `all` / void lookups / includes
without SPF, revoked DKIM keys, MTA-STS problems in testing mode,
nameservers without TCP or EDNS, SOA serial drift, low prefix diversity,
glue mismatch, TLSA in an unsigned zone, and www answered by a wildcard.
Warning and error strings are stable; key on them by prefix.

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

`-tcp-timeout` also bounds each stage of the application-layer probes
(TLS handshake, HTTP request, each redirect hop, the MTA-STS policy fetch)
and the whole probe phase is capped at three times it.

Worst-case wall time is bounded by the phases: the DNS phase and the
delegation trace run together for at most `2 × -t`, a DNSSEC bogus probe
can add `-t`, and the probe phase (TCP, TLS, HTTP, redirects, QUIC,
nameserver audit, late lookups) is capped at `max(3 × -tcp-timeout,
-quic-timeout + 1) + 1`. With the defaults (`-t 3 -tcp-timeout 2
-quic-timeout 2`) that is 6 + 3 + 7 = 16 s, reached only when every server
in every phase hangs; a dead resolver measures about 4 s and a healthy
domain about 3 s.

A `delv` lookup that times out in the first half of its budget is retried
once (`"retries": 1` in the record), so one dropped UDP query does not cost
the whole run. A run against a healthy domain takes about one second
when QUIC answers and about `-quic-timeout` when it does not; the extra
DNS lookups (DMARC, DKIM selectors, MX and NS targets, SPF includes, CAA,
TLSA, wildcard probe) are all cache hits on a warm resolver.

## Requirements

- `delv` and `dig` (BIND 9.18 or later, `+yaml` support) on `PATH`.
- `quicprobe` on `PATH`, at `../quicprobe/quicprobe` next to the binary or
  the working directory, or given with `-quicprobe`. It must support the
  `-ip` and `-t` flags.
- Go 1.27.1 (the `go` directive in `go.mod`; an older `go` downloads it).

## Sample reports

`testdata/reports/` holds pretty-printed reports produced by the current
binary: microsoftdrive.com (healthy, CDN-fronted, redirect chain ending
off-site; the most representative healthy web domain), jschmidt.org
(healthy, signed, mail-only), microsoft.jp.net (parked, HTTP only, null
MX; captured while one of its registrar's nameservers was unreachable
from the capturing host, so it also shows a nameserver error),
expired.badssl.com (certificate errors on a host inside a zone) and
dnssec-failed.org (DNSSEC bogus). Use them to write parsers against the
real shape.

## Tests

```
go test -short ./...   # unit tests, fixtures captured from real tool output
go test ./...          # also runs the network integration tests
```

Unit tests never touch the network: DNS answers come from captured
`delv`/`dig` output under `testdata/`, TLS and HTTP behaviour from local
`httptest` servers with certificates minted in-test, and the badssl.com,
DANE, wildcard and reserved-address cases run live only in the integration
suite.
