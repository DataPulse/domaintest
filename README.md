# domaintest

Checks the technical configuration of a domain name and prints one compact
JSON report.

```
domaintest [-4|-6] [-t seconds] [-tcp-timeout seconds] [-quic-timeout seconds] [-dns-concurrency n] [-no-hsts-preload] [-hsts-cache path] [-pretty] [-quicprobe path] [-delv path] [-dig path] <domain> [@dnsserver[:port]]
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
   CNAME is an error, and so is a name the resolver says has no address;
   a name whose lookup never completed is listed in `unresolved` and
   warned about, since an unanswered query is not a denial) and every
   address is asked
   for the zone SOA non-recursively over UDP, over TCP and with EDNS/DNSSEC
   in one `dig` run: no TCP or no EDNS is a warning, SOA serial drift
   between servers a warning. An address that answers nothing is asked once
   more before it counts as unreachable (`retries: 1` on the server entry),
   since one dropped UDP query is not a broken nameserver.

   The two ways a server can fail are weighed differently. One that answers
   and disclaims authority is proof of lameness, so it is an error however
   many of the name's addresses do it. One that never answers proves
   nothing by itself, so it is an error only when every address of that
   name is silent, and a warning while the rest of the name still answers
   authoritatively: a single unresponsive anycast node behind a healthy
   quorum is a flaky node, not a broken delegation. Fewer
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
   `hostname_mismatch`, `self_signed`, `incomplete_chain`,
   `untrusted_root`, `invalid` or `handshake_failed`; anything but `valid`
   is an error.

   `valid` means the chain **as served** verified against the trust store
   at probe time. It is not a statement about revocation, which is not
   checked, and the key and signature algorithm are reported but not
   judged.

   `incomplete_chain` and `untrusted_root` are the same x509 error to Go
   and are separated by evidence, never by the issuer's name. When the
   chain does not verify as served, the intermediate named by the leaf's
   AIA URL is fetched and the chain retried: if it then verifies, the
   server merely omitted the intermediate and the result is
   `incomplete_chain`, with the URL that was fetched named in `error`.
   If it still does not verify, or there is no AIA URL, or the fetch
   fails, the result is `untrusted_root`. A CA's name cannot distinguish
   these: `incomplete-chain.badssl.com` is issued by something calling
   itself Let's Encrypt and chains to a root in no trust store, so it is
   correctly `untrusted_root`. The AIA URL appears only in `tls.error` on
   an address classified `incomplete_chain`; there is no AIA field in
   `tls.cert`, and the CAA issuer table is a name lookup that says nothing
   about whether a chain validates.

   Because `incomplete_chain` verifies only after that repair, a caller
   distinguishing "correct as served" from "correct once repaired" should
   treat `valid` as the former and `incomplete_chain` as the latter:
   browsers usually repair it themselves, while curl, Java and some mobile
   clients do not. The certificate's subject, issuer, validity, days
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
    `google, selector1, selector2, default, k1, s1, mail, dkim` alongside a
    random selector as a negative control (found selectors are reported, a
    revoked empty key warns, none found is a fact since selectors cannot be
    enumerated). If the control answers, the zone wildcards `_domainkey`
    and `dkim.wildcard` is set: every guess would answer, so no selector is
    reported. Checking that the record parses as DKIM is not enough on its
    own, since a wildcard can serve a valid key for every name; MTA-STS `_mta-sts` record
    and, when present, the policy at
    `https://mta-sts.<domain>/.well-known/mta-sts.txt` fetched with full
    certificate verification, its host resolved through the tool's own
    validating lookups rather than the system resolver, and compared with
    the MX set (problems are errors in `enforce` mode, warnings otherwise);
    TLS-RPT presence. A null MX is reported as "accepts no mail". No SMTP
    connection is made. No finding ever names the resolver used.
11. **CAA** (`caa`): the certificate each host actually served is compared
    with the CAA records that govern that host, using a table of CA
    organisations to CAA identifiers. `caa` holds nothing but `hosts`, with
    one verdict for `apex` and one for `www`, so no value can be read as
    the domain's when it is only the apex's. Each verdict carries
    `published` (the records at that name, empty when it publishes none),
    `effective` (the set that governs it after RFC 8659 climbs to the
    closest ancestor with a CAA set, so a www without records shows the
    apex set here), `issuer`, `permitted` and `note`. `permitted` is true
    when no records govern the name, since any CA may then issue, and
    absent only when nothing could be judged: no certificate observed, or
    an issuer not in the table, with the note saying which. A wildcard
    certificate is checked against `issuewild` when the set has one, so a
    CA allowed to issue may still be forbidden to issue wildcards. A CA
    the records forbid is an error naming the host.
12. **DANE / TLSA** (`tlsa`): `_443._tcp.` records for apex and www are
    matched against every address's served chain per usage, selector and
    matching type. No match anywhere is an error; records in an unsigned
    zone are a warning because DANE clients ignore them. `signed` says
    whether the TLSA answers, positive or negative, were DNSSEC-validated:
    in a signed zone the denial of a missing TLSA set is itself signed, so
    `signed` is true there even with `result: none`.
13. **Wildcard** (`wildcard`): three unique random 12-letter labels under
    the domain are looked up for A and AAAA. `status` is `present` when
    every one of them answers, `absent` on the first definite denial, and
    `unknown` when a probe never came back, so a silent lookup can never
    read as a clean zone. `determined_by` says what settled it. A probe is
    judged from both of its lookups together, because a wildcard CNAME
    answers A with the CNAME while returning NXRRSET for AAAA. The denial
    that ends the check is any definite answer with nothing in it, NODATA
    as well as NXDOMAIN: signed zones behind synthesised NSEC (Cloudflare's
    "black lies", among others) never say NXDOMAIN at all. `consistent`
    says whether the probes answered alike; a catch-all that varies its
    answers is still a catch-all, so the variance qualifies the verdict
    rather than deciding it, and `consistent` is null unless the status is
    `present`. When www resolves to exactly what one probe answered the
    report says `www_via_wildcard` (and www carries `via_wildcard`) with a
    warning; a wildcard on its own is reported without a finding.
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
`dns_concurrency`, `reserved_addresses` (when any), `hsts_preload`,
`hsts_preload_covered_by` and `hsts_preload_error` (unless disabled),
`errors`, `warnings`, `ok`, `elapsed_ms`.

Each address entry under `web.apex` / `web.www` (`ipv4[]`, `ipv6[]`) has
`ip`, `80`, `443` (open / refused / timeout / unreachable / error /
skipped), `http` and `https` (status, location, server, hsts, error),
`tls` (chain, chain_problems, version, alpn, cipher, tls10, tls11, cert,
chain_length, error), `tlsa` (match / mismatch / none, only when TLSA records exist) and
`quic` (every address). Each host has `same_as_apex`, `via_wildcard`,
`redirects` (per family: hops, ended, final_url, external, loop, error) and
`cert_consistent`.

`web` is an empty object when the name has no usable addresses (no
A/AAAA, NXDOMAIN, bogus zone): callers must not assume `web.apex` exists.
`mail` and `nameservers` are absent for a name that is not a zone apex.
`mail` is also absent for a name that cannot receive mail at all: one
outside the global DNS (`reserved_name`) or one that does not exist
(NXDOMAIN). There is nothing to configure, so a missing DMARC record is
not a finding.

Conventions inside the new sections: arrays are always present (empty
rather than null), booleans are always present, strings are omitted when
empty, and an object is omitted only when the whole check did not apply
(`glue` when the parent could not be asked or no nameserver address was
known to compare it against, `tls` when 443 did not answer, `quic` when
quicprobe was not run).

The exception is the aggregates over the audited server set, which are
`null` when nothing was audited: `serials_consistent` is null when no
nameserver answered authoritatively, and `ipv4_prefixes_24` /
`ipv6_prefixes_48` are null when no nameserver address was examined. A
check that examined nothing reports unknown rather than a pass, so
`serials_consistent: true` now means the serials were actually compared.
The wildcard section's `consistent` is null the same way, whenever the
status is not `present` and there was therefore nothing to compare.
Consumers reading these as plain booleans or integers must handle null.
Per-lookup objects carry `retries: 1` when the first delv attempt timed
out and the retry answered, and so do nameserver entries whose first audit
query went unanswered.

Error and warning text never names the local end of a connection. Go
reports a network failure as `read tcp4 10.0.0.5:46962->93.184.216.34:443:
i/o timeout`; findings carry only the cause, `i/o timeout`, because the
preamble names the vantage point and changes its ephemeral port on every
run, which would make two identical results differ. The address that was
probed is already named by the finding.

Findings that can repeat across a host's addresses are reported once with
a count rather than once per address, in the same shape the nameserver
audit uses: `apex: certificate handshake failed on 7 of 7 addresses: read:
connection reset by peer`. Distinct causes stay distinct, and the
per-address detail remains in the `web` section.

Errors (set `ok` to false): apex NXDOMAIN, missing NS, DNSSEC bogus or
SERVFAIL, delegation mismatch / not delegated / no child answer / lame
zone, lookups that failed or timed out, resolver unreachable over an
enabled family, reserved addresses in DNS, any certificate chain problem,
every address 5xx on a port, redirect loops or over-long chains, DMARC
records that are multiple or unparsable, SPF permerrors (over the lookup
limit, multiple records), `+all`, unknown SPF mechanisms, MX targets that
are CNAMEs, IP literals, non-existent or without an address, MTA-STS problems in enforce mode,
nameservers that are CNAMEs, unresolvable, unreachable on every one of
their addresses, or not authoritative, fewer than two nameservers, missing glue, a certificate
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
without SPF, revoked DKIM keys, a zone that wildcards `_domainkey` (which makes every
selector answer, so none can be verified), MTA-STS problems in testing mode,
nameservers without TCP or EDNS, a nameserver address that never answered
while the name's other addresses are authoritative, SOA serial drift, low
prefix diversity,
MX targets and nameserver names whose address lookup did not complete (a
gap in the check, not a fault in the domain, and marked `unresolved` in
the report), an audit that reached no nameserver at all,
glue mismatch, TLSA in an unsigned zone, and www answered by a wildcard.
The SOA drift warning names each nameserver with the address that answered,
`ns1.example.(192.0.2.1)=9957`, since which address disagrees is the point.
Warning and error strings are stable; key on them by prefix.

## DNS concurrency

One run makes about 40 `delv` invocations and wants roughly 18 of them in
flight at once, each validating DNSSEC in its own process. That is free on
a workstation and ruinous on a small host running several domains at once:
on a two-vCPU worker at five concurrent runs the lookups miss their
deadlines through scheduling delay alone, with the resolver still idle.

`-dns-concurrency` caps how many DNS tool processes one run may have
running, so a caller keeps its own job-level parallelism instead of
trading it away. The default is twice the CPU count with a floor of 4,
which leaves a large machine effectively unbounded and protects a small
one without anyone passing a flag; `0` restores the old unlimited
behaviour. The value in force is echoed as `dns_concurrency` in the
report. Waiting for a slot is bounded by the same budget as the lookup
itself, so a saturated host degrades to ordinary timeouts.

The cap covers `delv` and `dig` only. `quicprobe` waits on the network
rather than competing for CPU, and queueing it behind DNS work would cost
QUIC answers for nothing. The resolver-reachability probe is also exempt:
it measures the configured resolver rather than the domain, so letting a
target's hung lookups starve it would turn a slow domain into a false
claim that the resolver is down.

## Timeouts

Defaults assume a well-connected vantage point such as an AWS host: a
server that cannot complete a handshake in two seconds is dead or
misconfigured.

`-t` (default 3 s) bounds each wave of `delv` lookups and the delegation
trace (which gets twice the budget with half of it per query, so one slow
root or TLD server does not sink the whole trace). The lookups run in two
waves, the fixed records first and then the ones those answers name (MX
targets, nameserver addresses, DKIM selectors, SPF includes), and each
wave gets its own `-t`. Sharing one allowance made the first wave's
queueing come out of the second, so a busy host lost every MX and
nameserver address at once and the report read as a domain with no
nameservers.

`-tcp-timeout` (default 2 s) bounds each TCP connect to 80 and 443.

`-quic-timeout` (default 2 s) bounds each QUIC handshake. A host without a
UDP 443 listener never answers, so every non-QUIC site would otherwise pay
the full `-t`; servers that do speak QUIC, or actively refuse it, answer
within tens of milliseconds.

`-tcp-timeout` also bounds each stage of the application-layer probes
(TLS handshake, HTTP request, each redirect hop, the MTA-STS policy fetch)
and the whole probe phase is capped at three times it.

Worst-case wall time is bounded by the phases: the DNS phase (two waves of
`-t` each) and the delegation trace run together for at most `2 × -t`, a
DNSSEC bogus probe
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
TLSA, wildcard probes) are all cache hits on a warm resolver. The wildcard
check stops at its first definite answer, so it costs two queries on a zone
that denies a random name, none at all when www is NXDOMAIN, and six only
when a wildcard is really there.

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

## Names outside the global DNS

A name reserved by RFC is not served by the public DNS, and a validating
resolver answers it locally. The denial it synthesises is unsigned, so
`delv` reports a broken trust chain and the report would otherwise turn the
resolver's own behaviour into a security verdict about the domain:
`foo.invalid` came back as DNSSEC bogus.

Such a name now carries `reserved_name` (the RFC that reserves it), its
DNSSEC state is `unknown` rather than `bogus`, the delegation and zone
checks are skipped, and one warning explains why. The suffixes are
`invalid`, `test`, `localhost`, `example` (RFC 6761), `local` (RFC 6762),
`onion` (RFC 7686) and `home.arpa` (RFC 8375). `example.com` and its
siblings are reserved for documentation but are real delegated names, so
they are checked like any other domain.

`chain_problems` lists every defect of a certificate, headline first, while
`chain` keeps naming the single most urgent one. A certificate can be both
expired and served for a name it does not cover, and an operator who
renewed it on the strength of `chain` alone would still have a broken site.

`ended` says why a redirect chain stopped: `final` (a terminal response),
`external` (the next hop left the zone and was deliberately not followed),
`loop`, `hop_limit` or `error`. A chain that hands off to an external host
is finished rather than truncated, and both cases have no `final_url`, so
the reason is the only thing that separates them.

A nameserver that answers authoritatively but sends no SOA carries
`no_soa`, so an absent `serial` is a recorded fact rather than a missing
key.
