# domaintest

Checks the technical configuration of a domain name and prints one compact
JSON report.

```
domaintest [-4|-6] [-t seconds] [-tcp-timeout seconds] [-quic-timeout seconds] [-max-time seconds] [-dns-concurrency n] [-no-hsts-preload] [-hsts-cache path] [-redirectlog] [-pretty] [-quicprobe path] [-dog path] [-dig path] <domain> [@dnsserver[:port]]
domaintest -warm-hsts-cache
domaintest -version
```

`-version` prints the build's version and exits 0. The version is whatever
the builder stamped with `go build -ldflags "-X main.version=<commit>"`.
scrape's worker image stamps the full commit it vendored. An unstamped
build reports the commit Go recorded from the source tree, with `-dirty`
appended when the tree had uncommitted changes, or `devel` when there is
no such record. Every report carries the same value as `version`. The
variable must stay `main.version`, a string: `-X` silently ignores a name
that does not exist.

`-redirectlog` follows each name's redirect chain (§8 below) and reports
it. It is off by default: following a chain walks the site the way a
visitor would, and that belongs to a browser (scrape's renderer records the
chain it actually followed, including meta-refresh and script navigations
and from non-cloud addresses). Without it the per-address `GET /` on 80
and 443 (§7) still runs, so the scheme upgrade, HSTS, `redirect_self` and
per-address consistency are still checked. Every report says which way it
ran in `redirect_log`.

Like `dig`, the optional `@dnsserver` may appear anywhere on the command
line. Without it the system resolver is used. A port may be appended
(`@127.0.0.1:5353`, `@[::1]:5353`); without one the default 53 applies.
The resolver must validate DNSSEC: every trust level and DNSSEC verdict in
the report is its verdict (see §1). In production it is the worker's own
Unbound, the same resolver live DNS uses.

The domain may be given as a U-label (`münchen.de`) or an A-label
(`xn--mnchen-3ya.de`), in any case, with or without a trailing dot. IDNA
2008 lookup rules apply. The report's `domain` is always the A-label and
`unicode_domain` carries the U-label form when the two differ.

## What it checks

1. **DNS records** with `dog`, the DNS client the rest of the DataPulse
   stack uses: A, AAAA, MX, TXT and NS at the apex, A and AAAA for `www.`,
   plus DS and DNSKEY. Every answer carries its trust level (`secure` /
   `insecure`), which is the resolver's verdict: `secure` when it set AD,
   having authenticated the whole answer, CNAME chain and denial of
   existence included. So a signed `www` CNAME into an unsigned CDN reads
   `insecure`, and so does every missing .com, .net and .org name and the
   DS denial of every unsigned delegation under them: those denials are
   NSEC3 opt-out spans, which prove nothing about the name (RFC 5155
   §9.2). Live DNS reports the same AD bit, so the two tools agree. Whether
   the resolver validates at all is read from the root NS answer the
   reachability check already asks for (the root zone is signed):
   `dns.resolver_validates` is false when it came back without AD, and
   then no answer carries a trust level and `dnssec.state` is `unknown`
   with the reason, rather than every signed zone reading as `insecure`.
   It is null when the resolver answered over no family. dog checks names
   before sending them and refuses an `xn--` label that is not a valid IDN
   (`xn--bad` is punycode for two control characters), which domaintest's
   lenient input accepted until dpdomain refused control characters in
   every mode (2026-10-07; it is now a usage error). Any other name dog
   refuses is never queried: its lookups fail saying dog cannot query it,
   and `dnssec.state` is `unknown` with that reason rather than a verdict on
   the resolver.
   Until 2026-10-07 every lookup ran `delv`, which validated by itself.
   That cost about 36 ms of CPU per lookup (process start-up, not
   cryptography) against dog's 2, about 1.6 CPU-seconds a run, which on a
   two-vCPU worker running five domains turned into lookups missing their
   budgets and being reported as the domain's faults. Its own verdicts
   also disagreed with the resolver's on opt-out denials, reserved names
   and zones whose servers only the resolver could reach. Apex or www addresses
   inside reserved ranges (RFC 1918, loopback, link-local, CGNAT,
   documentation, multicast, ULA, and the IPv6 forms that carry such an
   IPv4 address: NAT64, 6to4, IPv4-compatible) are an error and are not
   probed (`reserved_addresses`, ports `skipped`). The ranges and the
   reasons are dpdomain's `ipnorm.Reserved`, shared with every other
   DataPulse tool (since 2026-10-06; before, domaintest kept a list of its
   own and called NAT64 public).
2. **DNSSEC state**: `secure`, `insecure`, `island` (DNSKEY but no DS),
   `bogus` (the resolver fails the lookup but `dig +cd`, checking
   disabled, gets the data; with the resolver's Extended DNS Error when it
   sends one; never for a zone whose parent publishes no DS, where
   a lookup that fails and then answers with checking disabled is a flaky
   server, reported `servfail`), `servfail`, or `unknown`. A published DS and
   DNSKEY are not enough for `secure`: the resolver must have authenticated
   the DNSKEY answer. A DS whose algorithm or digest the validator does
   not support makes it treat the zone as unsigned, which is reported as
   `insecure` with a detail saying so. A name that does not exist
   (NXDOMAIN) is `nonexistent`: there is no zone to judge, and the detail
   says whether the parent's denial of existence validated. Under an
   opt-out parent (.com, .net, .org) it did not. Where the parent proves the
   denial (.se, for instance), every lookup of such a name can carry trust
   `secure` and the TLSA section `signed: true`; neither means the name is
   signed.
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
   between servers a warning. A reserved address (as for apex and www) is
   never queried: the server entry carries `reserved` (the reason) and an
   `error` saying it was not queried, and the name fails as
   `ns_reserved_address`. `ns_domains` lists the registrable domains the
   nameserver hostnames sit under. They are names, not network ownership:
   one provider can use several (Route 53: awsdns-NN.com, .net, .org and
   .co.uk) and vanity nameservers hide the provider, but six /24s under two
   of them is less diversity than the /24 count suggests. All under one is
   info (`ns_single_domain`). A nameserver published at 10.x or 169.254.x is
   unreachable from the Internet, and querying it would send the probe's
   DNS into the network the probe runs in. The delegation trace is `dig
   +trace`, which follows the referral glue itself and has no way to skip
   an address, so a reserved glue address is still queried there. An
   address that answers nothing is asked once
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
   IPv6 in one /48 is a warning. For in-bailiwick nameservers (names at or
   under the zone, whether or not they resolved: one without glue usually
   cannot be resolved at all) the parent's
   glue is compared with the zone's own addresses (missing glue is an
   error, a differing address a warning). A parent answer that is not a
   referral, such as REFUSED or SERVFAIL, says nothing about glue, and
   `glue` is then omitted. No zone transfer is ever
   requested.
5. **Web reachability**: TCP connect to ports 80 and 443 on every A and
   AAAA address of the apex and `www.` (probed separately, since the TLS
   name and Host header differ even when addresses are shared). Port 25 is
   deliberately not probed. At most 16 addresses are probed at once across
   both names, and at most 16 `quicprobe` processes run at once, so a zone
   publishing hundreds of addresses cannot exhaust the host's sockets or
   processes. What each external tool prints is kept up to 1 MB.
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
   AIA URL is fetched and the chain retried. If it still does not verify,
   the fetched certificate's own AIA URL is followed in turn, up to three
   fetches, since an intermediate can be signed by a newer root that the
   trust store only knows through a cross-signature: the leaf of
   `incomplete-chain.badssl.com` names Let's Encrypt YR1, YR1 is signed by
   ISRG Root YR, and only YR1's AIA leads to Root YR cross-signed by ISRG
   Root X1, the root the distribution trusts. If the chain verifies along
   the way, the server merely omitted intermediates and the result is
   `incomplete_chain`, with every URL fetched named in `error`. If it
   still does not verify, or there is no AIA URL, or a fetch fails, the
   result is `untrusted_root`. The trust store is the system's (the
   distribution's CA bundle); domaintest adds no roots of its own. The AIA URL is written by
   whoever made the leaf, and any server can present a leaf it made, so
   the fetch is held to the rules of the other probes: plain `http` only,
   a public address only (never a reserved one, such as a cloud metadata
   address), no redirects, 64 KB at most, inside the run's deadline, and
   each URL fetched once per run. A CA's name cannot distinguish
   these; only verifying the repaired chain can (until 2026-10-06 one
   fetch was made, and `incomplete-chain.badssl.com` was wrongly reported
   as `untrusted_root`). The AIA URL appears only in `tls.error` on
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
   certificates that differ in validity or in the names they cover.
   `cert_consistent` records whether the leaves are identical; a CDN
   rotating valid certificates for the same names serves different leaves
   to no effect, and that is not a warning. Two extra handshakes test whether TLS 1.0 and
   TLS 1.1 are still accepted (`tls10`, `tls11`: true when the handshake
   completes, false when the server refuses it, null when it was never
   tested because no connection was made or nothing answered before the
   deadline; info), and negotiating less than TLS 1.3
   is info. The main handshake offers only `http/1.1` via ALPN so that the
   HTTP request below can reuse the connection; which versions the address
   serves is reported in `http_versions` (§9).
7. **HTTP** (`http` on 80, `https` on 443, per address): one `GET /` with
   the proper Host header; status, Location and Server header are
   recorded from the final response (interim 1xx responses such as 103
   Early Hints are skipped), the `Alt-Svc` header as `alt_svc`, plus the parsed `Strict-Transport-Security` header
   (`max_age`, `include_subdomains`, `preload`). Every address answering
   5xx on a port is an error, some of them a warning, every address 4xx a
   warning. Port 80 serving content instead of redirecting to https is a
   warning, as is an HSTS max-age under 180 days. Upgrading to https with a
   temporary redirect (302, 303, 307) instead of a permanent one (301, 308)
   is info (`http_redirect_temporary`): only a permanent one is remembered.
   Some addresses of a host failing on 80 (refused, silent, or reset after
   connecting) while others answer, and 443 working on the failing ones, is
   a warning that names each (`http_port80_partial`): the per-address
   entries alone left one silent CDN node out of twelve unreported. An
   address down on both ports is `web_no_listener`; every address failing
   on 80 with 443 up is an HTTPS-only site and not a finding. HSTS absence is a fact,
   not a warning. `hsts_preload` says whether browsers enforce HSTS for the
   name regardless of the header, read from Chromium's preload list (see
   **HSTS preload list** below): `preloaded`, `absent` or `unknown` (the
   list could not be obtained; `hsts_preload_error` says why, with resolver
   addresses removed). When an ancestor entry rather than the name itself
   makes it preloaded, `hsts_preload_covered_by` names that ancestor, so a
   name under `app`, `bank`, `dev` or `page` reads preloaded with the TLD
   as the cover. `hsts_preload_include_subdomains` says whether the entry
   that preloads the name covers its subdomains (always true through an
   ancestor), and so whether www is preloaded too: port 80 on a preloaded
   www is info (`http_cleartext_preloaded`), as on the apex. A preloaded domain whose served header no longer meets the
   preload bar (max-age of a year, includeSubDomains, preload), or a header
   that carries `preload` without meeting it, is a warning.
   `-no-hsts-preload` skips the check entirely.
8. **Redirect chains**, only with `-redirectlog` (`redirects`, per name
   and address family; without the flag the key is absent and none of the
   chain findings below can be raised): from
   `http://<name>/` on the first address of the family, following
   Location headers up to ten hops while the target stays apex or www.
   Ordinary sites chain four to six (scheme upgrade, apex to www, path
   normalisation, locale, session), so a lower limit fails normal domains;
   browsers allow 20 and curl 50. A loop is an error: it is what the
   server sent during this run, and a client following it would never
   arrive. A loop over both families that took the same path is one
   finding naming both. Running out of hops is a
   warning: the follower stopped, so whether the chain ends is unknown,
   and asserting a fault from that would be the vacuous negative again.
   A chain that breaks after it started or ends in 4xx/5xx is a warning,
   and an external target is recorded as `external` and not followed. A
   hop from https back to http is `redirect_downgrade` (warn), once per
   host for the families that did it. A Location with a scheme other than
   http or https, or a port outside 1-65535, ends the chain broken. A chain is a property of the name, so
   it is followed once per family, unlike the per-address probes above.
   Each hop records `url`, `status` and the `location` the server sent
   (verbatim, relative or absolute), and a loop's message ends with the
   URL that closed it, so a page redirecting to itself
   (`https://x/ (301) -> https://x/`) reads differently from a chain sent
   back a step. The follower defends itself: at most ten hops, a stop at
   the first repeated URL (compared as a request, so a host name's case or
   a default port spelled out does not hide a loop), a per-hop timeout inside the probe budget, 64 KB
   of response head, and only apex and www are ever contacted. A Location
   over 4096 bytes is not followed: the chain ends broken and the hop
   records it clipped, with the original length, so a hostile server
   cannot bloat the report.

   **Consistency.** A run asks the same URL several times: once at each
   address, and, with `-redirectlog`, again as a hop of each family's
   chain. A server should
   give one answer to one request. When those answers differ in status or
   in where a redirect points, `http_response_inconsistent` (warn) names
   the URL and every answer with its count, such as
   `https://example.com/ answered differently within one run: 200 (13 of 14); 301 -> https://example.com/ (1 of 14)`.
   A per-address probe sent back to the URL it asked for is
   `redirect_self` (fail). Both compare only what the run already saw;
   nothing is fetched again, so a server that varies may look consistent
   on one run and not on the next. Redirects are compared by scheme, host,
   port and path: a query string often carries a per-request token, and a
   default port, a relative Location or the host's case changes nothing.
   A refusal (401, 403, 407, 417, 429) answers the client rather than the
   URL and is not compared. Seen on ip-house.com (2026-10-05), whose
   CloudFront cache key ignored the Host header: the apex was sometimes
   served www's redirect, pointing at itself, and www sometimes the apex's
   page.
9. **HTTP versions** (`http_versions`, per address, HTTPS only; port 80 is
   plain HTTP/1.1 and is the `http` result): `http1_1`, `http2`, `http3`
   and `h3_advertised`, each true, false, or null when the question could
   not be put (no connection, a timeout, nothing probed), as for `tls10`.
   `http1_1` is the main handshake (offering only `http/1.1`) and its GET:
   true when a response came back, false when the port is refused, the
   server ends the handshake with alert 120 (`no_application_protocol`) or
   the session carries something that is not HTTP/1.1. `http2` is a fresh
   handshake offering only `h2`, run beside the TLS 1.0/1.1 ones and even
   when the main handshake failed (an h2-only server refuses that one):
   true when `h2` was negotiated, false when the handshake completed
   without it or ended in alert 120; no HTTP/2 request is sent, ALPN being
   what browsers act on. `http3` is the sibling `quicprobe` tool's QUIC
   handshake with ALPN `h3`, on every address of both names (every address
   carries its `quic` object): true when it completed, false when an
   endpoint answered and refused, and, when nothing answered on UDP 443,
   false only if nothing advertises h3 either; an address whose `Alt-Svc`
   offers h3 but is silent on UDP may be filtered on the probe's path, so
   it is null. `h3_advertised` is whether the HTTPS response's `Alt-Svc`
   lists `h3` (or an `h3-NN` draft); HTTPS DNS records are not consulted.
   Per host (for 1.1 and 2, among the addresses whose 443 answered: no
   HTTPS at all is `https_unreachable`'s finding), no address serving
   HTTP/1.1, HTTP/2 or HTTP/3 is info
   (`http1_1_absent`, `http2_absent`, `http3_absent`), HTTP/2 on only some
   addresses is info (`http2_partial`), and an address advertising h3 that
   did not answer it is a warning (`h3_advertised_unreachable`): browsers
   try it and fall back. The "QUIC/h3 works on another probed address"
   info (`quic_partial`) is unchanged. Until 2026-10-07 the report carried
   `tls.alpn` instead, which could only ever say `http/1.1`.
10. **Mail** (`mail`, zone apexes only; absent for a host inside a zone,
    like `nameservers`, since mail policy lives at the zone): DMARC at
    `_dmarc` (missing or `p=none` warn,
    multiple or unparsable records error, `pct` below 100 warns; tag values
    are case-insensitive, so `p=Reject` is reject, and a malformed `pct` or
    `sp` warns); SPF is
    evaluated, not just found: include/redirect chains are followed and
    DNS-querying terms counted (more than 10 is a permerror and an error,
    as are multiple records, `+all`, an include loop and unknown
    mechanisms; `?all`, `ptr`, a missing `all`, more than two void lookups
    and includes without SPF warn; an `ip4`/`ip6` entry another prefix of
    the same record and qualifier already covers is info,
    `spf_redundant_ip`). `void_lookups` counts only the lookups that can be
    evaluated without a sender: an `exists` mechanism or a macro depends on
    who is sending, so a void lookup it may cost at evaluation time is not
    counted. Every evaluation is charged as RFC 7208
    §4.6.4 requires, so a domain included from two places costs its
    lookups twice. A `redirect` is ignored when the record has an `all`
    (§6.1), and the `all` a redirect target ends with is the domain's: it
    is reported in `all`, and `+all` or `?all` reached that way, or `+all`
    in an included record, is judged as if the apex said it. A void lookup
    is an answer with no records; a lookup that never completed is not
    one, and is reported as unchecked instead. A TXT string is SPF only
    when `v=spf1` is followed by a space or nothing. Answer size is checked against RFC 7208 §3.4: the apex TXT
    reply a resolver without EDNS would get (header, question and every
    TXT record at the name, since verification tokens ride along) is
    reported as `txt_answer_octets` and warns above 450 octets and again
    above the 512-octet limit; an include whose own TXT reply exceeds 512
    octets warns too. Above 1232 octets, the EDNS buffer resolvers commonly
    advertise, the finding adds that nearly every lookup needs TCP. The
    size is the wire size: a TXT string longer than 255 octets is several
    character-strings, each with its own length octet. Every MX target must be a resolvable hostname that is not a
    CNAME or IP literal (errors); DKIM is probed at the selectors
    `google, selector1, selector2, default, k1, s1, mail, dkim` alongside a
    random selector as a negative control (found selectors are reported, a
    revoked empty key warns, none found is a fact since selectors cannot be
    enumerated). Each key found is described in `dkim.keys` (`selector`,
    `type`, RSA `bits`, `error` when `p=` is not a usable key): an RSA key
    under 1024 bits fails (verifiers reject it, RFC 8301 §3.2), under 2048
    is info (`dkim_key_weak`: RFC 8301 recommends 2048, but a quarter of the
    reference set, Microsoft 365's default among them, uses 1024), an
    unusable key warns (`dkim_key_invalid`). A selector that is a CNAME to a
    name that does not exist is listed in `dkim.dangling` and is info
    (`dkim_selector_dangling`): it is how a Microsoft 365 tenant that never
    rotated its keys looks (microsoft.com's own selector1 dangles), and
    nobody signs with it. If the control answers, the zone wildcards `_domainkey`
    and `dkim.wildcard` is set: every guess would answer, so no selector is
    reported. Checking that the record parses as DKIM is not enough on its
    own, since a wildcard can serve a valid key for every name; MTA-STS `_mta-sts` record
    and, when present, the policy at
    `https://mta-sts.<domain>/.well-known/mta-sts.txt` fetched with full
    certificate verification, its host resolved through the tool's own
    lookups against the configured resolver rather than the system's, every public
    address tried at once (a reserved one is never contacted), and compared with
    the MX set (problems are errors in `enforce` mode, warnings otherwise;
    `mode: none` withdraws the policy, so its mx lines are not judged);
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
    CA allowed to issue may still be forbidden to issue wildcards. A
    property with the critical flag (128) and a tag no CA defines forbids
    every CA (RFC 8659 §4.1). "Any CA may issue" is only said from lookups
    that answered: a www with no records of its own takes the apex set, so
    when the apex lookup failed, www is unknown too. A CA
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
    report says `www_via_wildcard` (and www carries `via_wildcard`). For a
    registrable domain that is the info finding `www_wildcard`: www has no
    host of its own. For a host inside a zone (`expired.badssl.com`) there
    is no finding, because its www is a name nobody publishes and a
    catch-all answering it is expected. A wildcard on its own is reported
    without a finding.
14. **Resolver reachability** over IPv4 and IPv6 (a root NS query per
    family). A family whose transport the resolver cannot use reads
    `skipped: resolver has no ipv6 address` (or ipv4): with
    `@127.0.0.1:8053` or any IPv4 literal, `ipv6` is always skipped even
    though `families` still lists it for the TCP and QUIC probes. That is
    expected, not a defect; key on the `skipped` prefix.

Steps 5 to 9 run over both IPv4 and IPv6 unless `-4` or `-6` is given.
DNS record data is fetched once; a literal `@server` address fixes the DNS
transport family. Every DNS lookup goes through `dog` to the configured
resolver, and its DNSSEC verdict is the resolver's AD bit.

## HSTS preload list

The preload answer comes from Chromium's `transport_security_state_static.json`,
not from a per-domain API call, so **the network is touched at most once per
host**. The list is fetched once (about 1.1 MB on the wire, gzipped by the
transport), reduced to the three fields a lookup needs (name,
`include_subdomains`, `policy`) and cached as TSV, a little over 2 MB. Every later run on that host, for any domain, reads the
cache.

- **Path**: `-hsts-cache`, defaulting to
  `<user cache dir>/domaintest/hsts-preload.tsv`, i.e. `$XDG_CACHE_HOME` or
  `$HOME/.cache`. `-hsts-cache -` disables caching and fetches every run.
- **Lifetime**: seven days, from the fetch time in the cache header. The
  intended deployment replaces its hosts every few hours, so the cache
  usually dies with the host first; a long-lived host refetches weekly. A
  refresh that fails falls back to the older copy, and
  `hsts_preload_error` says so while `hsts_preload` still answers. Delete
  the file to force a refresh.
- **Write failures**: a cache that cannot be written does not fail the
  run, which answers from the list it fetched, but `hsts_preload_error`
  carries the reason (without the path) so it is not silent.
- **Concurrency**: population is serialised with an exclusive `flock` on
  `/run/lock/domaintest-hsts.lock`, falling back to `<cache>.lock` when that
  directory is missing or unwritable, as in a container. The lock file is
  opened read-only, which is all `flock` needs, so a run shares the lock a
  root warm-up created. Parallel runs on a
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
- **Policy decides whether a header is owed**: `hsts_preload_policy` is
  Chromium's `policy` for the entry that covers the name. `bulk-legacy`,
  `bulk-18-weeks` and `bulk-1-year` entries were submitted through
  hstspreload.org and stay listed only while they serve a compliant header,
  so a missing or weak header on one is a warning. `google`, `custom`,
  `public-suffix` and the other hand-kept policies carry no such obligation:
  gmail.com is policy `google`, answers `https://gmail.com/` with a bare 301
  and no header, and that is reported as fact, not warned about. An entry
  with no policy is held to the requirement.
- **Which response is read**: the header is looked for on the apex's own
  `GET /` on 443. Redirects are not followed for this, deliberately: HSTS is
  per-host, so a header served by the redirect target says nothing about the
  name that was asked about. The warning names the status that was read. A
  request that failed before a response head arrived (a read timeout, a
  reset) is not a response without the header and produces no warning.
- **Cache format**: `#domaintest-hsts-preload v2`, lines of
  `name<TAB>0|1<TAB>policy`. A v1 cache fails the header check and is
  refetched; nothing needs deleting.
- **Semantics**: the list records enforcement, so there is no equivalent of
  the submission states `pending` and `rejected` that hstspreload.org
  reports; such domains read `absent`, which is what browsers do.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no errors found |
| 1 | the report contains errors (`"ok": false`) |
| 2 | usage error, or `dog`, `dig` or `quicprobe` not found |

## Report

Single-line JSON on stdout (`-pretty` indents). The object opens with a
header: `version` (the build, as `-version` prints it) and `timestamp`
(when the probe began, UTC, RFC 3339 to the second, such as
`2026-10-05T19:42:07Z`; it finished `elapsed_ms` later). The other
top-level keys are `domain`, `unicode_domain` (IDN only), `resolver`, `families`, `timeout_sec`,
`tcp_timeout_sec`, `quic_timeout_sec`, `max_time_sec`, `redirect_log` (whether chains were followed), `not_a_zone` and `enclosing_zone`
(hosts only), `dns`, `dnssec`, `delegation`, `web`, `certificates` (when any address served one), `mail`,
`nameservers` (zones only), `caa`, `tlsa`, `wildcard`,
`dns_concurrency`, `reserved_addresses` (when any), `hsts_preload`,
`hsts_preload_covered_by`, `hsts_preload_include_subdomains` and
`hsts_preload_error` (unless disabled),
`errors`, `warnings`, `findings`, `ok`, `deadline_reached` (only when
true), `elapsed_ms`.

Each address entry under `web.apex` / `web.www` (`ipv4[]`, `ipv6[]`) has
`ip`, `80`, `443` (open / refused / timeout / unreachable / error /
skipped), `http` and `https` (status, location, server, hsts, alt_svc, error),
`tls` (chain, chain_problems, version, cipher, tls10 and tls11
(null when untested), cert, chain_length, error), `http_versions` (§9),
`tlsa` (match / mismatch / none, only when TLSA records exist) and
`quic` (every address: supported, alpn, tls_version, server_addr,
handshake_ms, and on failure `reason`, `error` and, for `tls_rejected`,
`tls_alert` / `tls_alert_code`). `reason` is one of `timeout` (nothing
answered on UDP 443), `tls_rejected` (a QUIC endpoint answered but refused
the handshake; on a CDN this usually means HTTP/3 is not enabled for the
hostname, CloudFront sends alert 40 `handshake failure`), `resolve_failed`,
`version_negotiation`, `stateless_reset`, `transport_error`,
`application_error`, `listen_failed`, `invalid_args` or `other`. Each host has `same_as_apex`, `via_wildcard`,
`redirects` (only with `-redirectlog`; per family: hops with url, status and location, ended, final_url, external, loop, error) and
`cert_consistent`.

The certificate fields are per address except the name list: `cert.sans`
is not repeated on every address that served the certificate but kept
once under the top-level `certificates`, keyed by the certificate's
`fingerprint_sha256` (`"certificates": {"<fingerprint>": {"sans": [...]}}`).
Before 2026-10-06 each address carried its own copy, and the copies were
most of a report's size. `covers_apex`, `covers_www` and `wildcard` stay
on each address.

`web` is an empty object when the name has no usable addresses (no
A/AAAA, NXDOMAIN, bogus zone): callers must not assume `web.apex` exists.
`mail` and `nameservers` are absent for a name that is not a zone apex.
`mail` is also absent for a name that is itself an ICANN public suffix:
nobody receives mail at `com` or `co.uk`, so a missing DMARC record there
is advice to a registry that no caller can act on, and the eight DKIM
selector probes are wasted queries against a registry's nameservers.
Private suffixes such as `github.io` and `herokuapp.com` keep their mail
checks, being ordinary domains their owners operate. A name that is itself
a public suffix of either section carries `public_suffix: true`, which also
explains why `web.www` is absent for it.

`web.www` is absent unless the name is a **registrable domain**, meaning
one label below a public suffix as the Public Suffix List defines it.
`www` belongs to a registrable domain: `jeff.co.uk` is registrable, so
`www.jeff.co.uk` is a real name someone would configure, while
`www.old.reddit.com` is a name only this tool would ever ask for. Asking
for it got an answer from a catch-all, served with a `*.reddit.com`
certificate that cannot cover the extra label, and reported a hostname
mismatch on a healthy site.

The list is the right test rather than "is this a zone apex", in both
directions. A registrable domain stays registrable however odd its DNS
looks, and `blog.cloudflare.com` is a genuine delegated zone apex whose
`www` would be just as invented.
`mail` is also absent for a name that cannot receive mail at all: one
outside the global DNS (`reserved_name`) or one that does not exist
(NXDOMAIN). There is nothing to configure, so a missing DMARC record is
not a finding.

Conventions inside the new sections: arrays are always present (empty
rather than null), booleans are always present, strings are omitted when
empty, and an object is omitted only when the whole check did not apply
(`glue` when the parent could not be asked or did not answer with a
referral, `tls` when 443 did not answer, `quic` when
quicprobe was not run).

A name whose NS answer traversed a CNAME is never treated as a zone apex.
RFC 1034 forbids a CNAME coexisting with other data and an apex must carry
NS and SOA, so the records an NS query returns for such a name describe the
CNAME target's zone instead. `gist.github.com` is a CNAME to `github.com`,
so its NS query returns github.com's nameservers; auditing those for a zone
they do not serve produced a REFUSED from every one. Over half the
subdomains in a typical sample are CNAMEs, so this only shows up once a
test set contains them.

A name with no records at all gets the same verdict however its parent
zone denies it. A signed zone using compact denial of existence answers
NOERROR/NODATA rather than admitting a name is absent, so `nosuchhost` under
one provider returned NXDOMAIN and failed while the same name under another
returned NODATA and passed. When every apex lookup answered and none
returned a record, the report says the name has no records of any type and
fails, matching the NXDOMAIN case: a name someone created has at least one
record of some type, since a mail-only host still has an MX and a
verification host still has a TXT. Requiring every lookup to have answered
keeps a failed probe from being read as an empty name, and the per-type
presence warnings are folded into the one error.

The same rule governs three checks whose absence is only meaningful once
observed. A `_dmarc` lookup that did not complete sets `mail.dmarc.unresolved`
and warns that the lookup did not complete, rather than reporting no DMARC
record. A CAA lookup that did not complete leaves `permitted` null with a
note, because "any CA may issue" is a security-relevant all-clear that must
never be derived from a failed query; for the same reason `www` only
inherits the apex CAA policy when `www` itself answered that it publishes
none. A TLSA lookup that did not complete reports `result: unknown` with
`signed` false, rather than `none`, which would claim the domain has no
DANE.

The exception is the aggregates over the audited server set, which are
`null` when nothing was audited: `serials_consistent` is null when no
nameserver answered authoritatively, and `ipv4_prefixes_24` /
`ipv6_prefixes_48` are null when no nameserver address was examined. A
check that examined nothing reports unknown rather than a pass, so
`serials_consistent: true` now means the serials were actually compared.
The wildcard section's `consistent` is null the same way, whenever the
status is not `present` and there was therefore nothing to compare.
Consumers reading these as plain booleans or integers must handle null.
Per-lookup objects carry `retries: 1` when the first DNS attempt timed
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
every address 5xx on a port, redirect loops (with `-redirectlog`), DMARC
records that are multiple or unparsable, SPF permerrors (over the lookup
limit, multiple records), `+all`, unknown SPF mechanisms, MX targets that
are CNAMEs, IP literals, non-existent or without an address, MTA-STS problems in enforce mode,
nameservers that are CNAMEs, unresolvable, unreachable on every one of
their addresses, or not authoritative, fewer than two nameservers, missing glue, a certificate
issuer the CAA records forbid, and TLSA records matching no served
certificate. A bogus zone yields one DNSSEC error; the per-lookup failures
it causes are folded into it rather than listed one by one, and so is a
DMARC lookup that did not complete (`_dmarc` is inside the zone). MX
targets and SPF includes usually live in other zones, so their failures
still stand.

Warnings: everything in `findings` with severity `warn`, listed below.
`info` findings are configuration facts, not warnings, and appear only in
`findings`. The SOA drift finding names each nameserver with the address that
answered, `ns1.example.(192.0.2.1)=9957`, since which address disagrees is
the point.

### Findings

`findings` lists every result as `{code, severity, host, message}`:

- `code` is a stable snake_case identifier. Key on it, not on `message`,
  whose wording may change. A code always has the same severity.
- `severity` is `fail`, `warn` or `info`, and the set is closed. `fail`
  is what sets `ok` to false. `warn` is a defect worth fixing. `info` is a
  configuration fact that is normal for some well-run domains and is
  recorded rather than scored: an operator's choice to keep TLS 1.0 for
  legacy clients, or a parked name having no MX, means something only
  against a reference that domaintest does not hold.
- `host` is `apex`, `www`, a nameserver or MX host name, or empty for a
  finding about the domain as a whole.
- `message` is the sentence also found in `errors` (fail) or `warnings`
  (warn); an `info` message is in `findings` only. Messages
  state what was observed and nothing else: no advice, no citations. A
  consumer that wants to advise maps codes to its own guidance.

`errors` and `warnings` are kept for consumers that predate `findings`:
`fail` entries are exactly `errors` and `warn` entries are exactly
`warnings`, in the same order. Through 0392e4c, `warnings` also carried the
`info` entries. They were taken out once every consumer that colours by
the arrays had moved to `findings`, so a report from an earlier build has
more warnings than the same domain does now.

The severities were calibrated on 2026-10-05 against the flagship
apexes and subdomains in `testdata/calibration/reference.txt`. A finding
that most of those operators carry describes a choice, not a defect, and
is `info`. `go test -tags calibration -run Calibration -v` reruns that
check live and fails if any `warn` code fires on more than 20% of the
set.

| severity | codes |
|---|---|
| fail | `zone_unreachable` `apex_nxdomain` `apex_empty` `ns_absent` `lookup_timeout` `lookup_failed` `dnssec_bogus` `resolver_servfail` `resolver_unreachable` `delegation_mismatch` `not_delegated` `delegation_nodata` `delegation_no_answer` `delegation_lame` `delegation_trace_failed` `reserved_address` `ns_reserved_address` `cert_expired` `cert_not_yet_valid` `cert_hostname_mismatch` `cert_self_signed` `cert_incomplete_chain` `cert_untrusted_root` `cert_invalid` `cert_handshake_failed` `http_server_error` `redirect_loop` `redirect_self` `mx_null_mixed` `mx_target_invalid` `mx_target_ip_literal` `mx_target_cname` `mx_target_nxdomain` `mx_target_no_address` `mx_invalid` `dmarc_multiple` `dmarc_policy_missing` `dmarc_policy_unknown` `dmarc_invalid` `spf_multiple` `spf_lookup_limit` `spf_unknown_mechanism` `spf_pass_all` `spf_include_loop` `spf_invalid` `mta_sts_enforce_failed` `mta_sts_enforce_mx_uncovered` `ns_count_low` `ns_cname` `ns_no_address` `ns_lame` `ns_no_answer` `glue_missing` `caa_issuer_denied` `tlsa_mismatch` `dkim_key_too_short` |
| warn | `reserved_name` `apex_no_address` `web_no_listener` `https_unreachable` `cert_expiry_urgent` (under 7 days) `cert_mismatch_between_addresses` `cert_sibling_uncovered` `http_cleartext` `http_redirect_insecure` `http_server_error_partial` `http_client_error` `redirect_ends_error` `redirect_hop_limit` `redirect_broken` `redirect_downgrade` `http_response_inconsistent` `spf_absent` `dmarc_absent` `dmarc_unknown` `spf_void_limit` `spf_no_all` `spf_ptr_deprecated` `spf_neutral_all` `spf_include_invalid` `spf_include_missing` `spf_include_unchecked` `spf_problem` `dmarc_pct_invalid` `dmarc_subdomain_policy_unknown` `mx_target_unresolved` `dkim_selector_revoked` `dkim_wildcard` `mta_sts_failed` `mta_sts_mx_uncovered` `dnssec_dnskey_no_ds` `dnssec_unknown` `ns_partial_answer` `ns_no_tcp` `ns_no_edns` `ns_same_v4_24` `ns_unaudited` `ns_none_reached` `glue_differs` `hsts_preload_header_missing` `hsts_preload_header_weak` `dkim_key_invalid` `h3_advertised_unreachable` `http_port80_partial` |
| info | `not_a_zone` `reserved_nxdomain` `www_nxdomain` `www_no_address` `www_wildcard` `aaaa_absent` `mx_absent` `mx_null` `cert_expiry_soon` (7 to 29 days) `tls_legacy_versions` `tls13_absent` `hsts_short_max_age` `hsts_preload_directive_unmet` `hsts_preload_unknown` `http_cleartext_preloaded` `http_redirect_insecure_preloaded` `http_probe_refused` `https_not_verified` `dmarc_policy_none` `dmarc_partial_pct` `spf_txt_over_udp_limit` `spf_txt_near_udp_limit` `spf_include_txt_over_udp_limit` `soa_serial_differs` `ns_same_v6_48` `tlsa_unsigned_zone` `quic_partial` `address_not_probed_reserved` `run_deadline_reached` `dnssec_unsigned` `caa_absent` `mta_sts_absent` `tls_rpt_absent` `http1_1_absent` `http2_absent` `http2_partial` `http3_absent` `http_redirect_temporary` `dkim_key_weak` `spf_redundant_ip` `ns_single_domain` `dkim_selector_dangling` |

`host` names the probed name a finding is about when apex and www can
differ: web, TLS, HTTP versions, CAA verdicts and address facts (`apex`,
`www`), or the MX target or nameserver concerned. A finding about the
domain as a whole is `""`: DNSSEC, delegation, every mail finding (SPF,
DMARC, DKIM, MTA-STS, TLS-RPT), nameserver diversity and the absence of
CAA records.

What a domain does not publish is stated as an info finding when the
lookup answered that it is not there (never when it failed): an unsigned
zone (`dnssec_unsigned`), no CAA (`caa_absent`: any CA may issue), no
MTA-STS (`mta_sts_absent`) and no TLS-RPT (`tls_rpt_absent`), alongside
the older `aaaa_absent` and `mx_absent`. Until 2026-10-07 these appeared
only in the body of the report, so `findings` was not a complete list.

A zone no delegated nameserver answers for is reported as one finding,
`zone_unreachable`, and the probe stops there. For this to apply, the
parent zone must have returned a referral, which shows the probe's own
network works. The delegated servers must then have given no answer to
the trace, and the nameserver audit must have found every address of
every nameserver refusing or silent, or the nameserver having no address.
The message names what each server did:

`no delegated nameserver answers for the zone: ns1.example. not authoritative (REFUSED) on 2 of 2 addresses; ns2.example. no answer on 2 of 2 addresses`

Every other check depends on an answer from those servers, so none is
reported. The probe skips the web, mail, CAA, TLSA, wildcard and HSTS
preload checks. `web` is `{}`, and `mail`, `caa`, `tlsa`, `wildcard`
and the `hsts_preload` keys are absent. The resolver-reachability error
is still reported, since it describes the probe rather than the domain.
If one nameserver answers, or one nameserver's address lookup did not
complete, the zone is not called unreachable and the full report is
produced. Likewise a zone that answers with no NS records has answered.

Notes on the info rows:

- `http_probe_refused` is a 401, 403, 407, 417 or 429, either on every
  address or at the end of a redirect chain (`-redirectlog`). Why the server refused is not
  observable: a bot filter judging the client, a block on the network the
  probe runs from, or a page that really is private. From an AWS address,
  1-800-chase-credit-cards.com answered 403 to the same request that a
  non-cloud host was served. So the status says nothing about the site. A
  404 or 410 is still a warning.
- `https_not_verified` is an address whose port 80 refused the probe and
  whose port 443 did not answer. A block on the probe's network often drops
  the TLS handshake as well, so this is not reported as `https_unreachable`
  (a warning that HTTPS is missing): neither port was verified.
- `http_cleartext_preloaded` is plain HTTP on a host the HSTS preload list
  covers. No browser ever makes that request.
- A www name inside a zone (`www.app.example.com`) is not checked for a
  wildcard. The HSTS preload header requirement applies only to the
  list entry itself, not to names covered by an ancestor's
  `include_subdomains`.

## DNS concurrency

One run makes about 45 `dog` invocations and wants roughly 18 of them in
flight at once. While each was a `delv` validating DNSSEC in its own
process (until 2026-10-07), that was free on a workstation and ruinous on
a small host running several domains at once: on a two-vCPU worker at five
concurrent runs the lookups missed their deadlines through scheduling
delay alone, with the resolver still idle. dog costs about a twentieth of
the CPU, and the cap stays as a bound on the fan-out.

`-dns-concurrency` caps how many DNS tool processes one run may have
running, so a caller keeps its own job-level parallelism instead of
trading it away. The default is twice the CPU count with a floor of 4,
which leaves a large machine effectively unbounded and protects a small
one without anyone passing a flag; `0` restores the old unlimited
behaviour. The value in force is echoed as `dns_concurrency` in the
report. Waiting for a slot is bounded by the same budget as the lookup
itself, so a saturated host degrades to ordinary timeouts.

The cap covers `dog` and `dig` only. `quicprobe` waits on the network
rather than competing for CPU, and queueing it behind DNS work would cost
QUIC answers for nothing. The resolver-reachability probe is also exempt:
it measures the configured resolver rather than the domain, so letting a
target's hung lookups starve it would turn a slow domain into a false
claim that the resolver is down.

## Timeouts

Defaults assume a well-connected vantage point such as an AWS host: a
server that cannot complete a handshake in two seconds is dead or
misconfigured.

`-t` (default 3 s) bounds each wave of DNS lookups and the delegation
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
domain about 3 s. When the
`_mta-sts` record exists, the policy host's addresses are looked up in the
second wave rather than in series at the end. When the delegated nameservers were silent to the
trace, the nameserver audit runs first under its own allowance of the
same size, so the probes after it are not left with the remainder.

`-max-time` (default 18 s, `0` for none) is a deadline for the whole run.
The sums above are what each phase is allowed, and a server that is slow
at every stage can add to them; scrape kills a run at 20 s and keeps no
output, so the deadline makes sure a report is written first. Every
subprocess, connection, handshake and request stops at it. A run that
reaches it sets `"deadline_reached": true` and adds the info finding
`run_deadline_reached`. Whatever was still running reports its own
timeout. The report header carries the value as `max_time_sec`.

A DNS lookup that times out in the first half of its budget is retried
once (`"retries": 1` in the record), so one dropped UDP query does not cost
the whole run. A run against a healthy domain takes about one second
when QUIC answers and about `-quic-timeout` when it does not; the extra
DNS lookups (DMARC, DKIM selectors, MX and NS targets, SPF includes, CAA,
TLSA, wildcard probes) are all cache hits on a warm resolver. The wildcard
check stops at its first definite answer, so it costs two queries on a zone
that denies a random name, none at all when www is NXDOMAIN, and six only
when a wildcard is really there.

## What counts as a domain

Every rule is enforced in one place, `normalizeDomain`, and a violation is
a usage error (exit 2) with a message naming the actual problem.

The name is trimmed of surrounding space and one trailing dot, lower-cased,
and converted to A-labels, so `EXAMPLE.COM.` and `münchen.de` are accepted
and reported as `example.com` and `xn--mnchen-3ya.de`. It must be 253
octets or fewer. Each label must be 1 to 63 characters of letters, digits,
hyphen or underscore, and must not begin or end with a hyphen, so
`_dmarc.example.com` and `_443._tcp.example.com` are valid while
`-bad.com`, `bad-.com` and `a..b.com` are not. A domain given with a
leading hyphen reports that a label must not start with one, rather than
being mistaken for an unknown flag.

The top-level domain is stricter than the labels to its left. It is never
all digits (RFC 3696 §2), which is what separates a name from a
dotted-quad address, so `1.1.1.1` and `3.14` are rejected. It never
contains an underscore, so `foo._com` is rejected while `_dmarc.example.com`
is not. A digit elsewhere is valid and common, since RFC 1123 §2.1 relaxed
the older letter-first rule: `1password.com`, `7-eleven.com` and
`333oracle.xyz` are all accepted.

A single label is a valid input, so `com` and `co.uk` are checked and
carry `public_suffix: true`.

## Requirements

- `dog` (the DataPulse fork, with `--timeout`, from 1b5845d) on `PATH`, or
  given with `-dog`.
- `dig` (BIND 9.18 or later, `+yaml` support) on `PATH`, for the
  delegation trace, the nameserver audit and the checking-disabled probe.
- A DNSSEC-validating resolver (see §1).
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
dnssec-failed.org (DNSSEC bogus). The calibration fixtures, captured live
on 2026-10-05, are google.com, microsoft.com, facebook.com, oracle.com,
sap.com, icann.org, wikipedia.org, nic.cz, docs.github.com and
app.slack.com. Alongside them are parked defensive registrations from a
real portfolio: microsoft.ar, microsoft.org and nikonic.net. The delegation
cases are skvr.site (every nameserver refuses),
login-microsoft-virtualperu.com (refusing and silent), oraclehealth.com
(half its nameservers refuse, so it is not unreachable) and iboracle.com
(the zone answers with no NS records). These
fixtures were captured before `findings` existed and while chains were
always followed, so they show the `-redirectlog` shape, and the tests rebuild
it from each report's sections. Use them to write parsers against the
real shape.

## Tests

```
go test -short ./...   # unit tests, fixtures captured from real tool output
go test ./...          # also runs the network integration tests
go test -tags calibration -run Calibration -v   # live severity calibration
```

Unit tests never touch the network: DNS answers come from captured
`dog`/`dig` output under `testdata/` (`testdata/dog/README.md` says where
each dog capture came from), TLS and HTTP behaviour from local
`httptest` servers with certificates minted in-test, and the badssl.com,
DANE, wildcard and reserved-address cases run live only in the integration
suite.

## Names outside the global DNS

A name reserved by RFC is not served by the public DNS, and a validating
resolver answers it locally, so whatever it says describes the resolver,
not the domain. While lookups ran `delv`, the unsigned local denial read
as a broken trust chain and `foo.invalid` came back as DNSSEC bogus.

Such a name now carries `reserved_name` (the RFC that reserves it), its
DNSSEC state is `unknown` rather than `bogus`, the delegation and zone
checks are skipped, and one warning explains why. No delegation trace and
no nameserver audit run: `delegation.status` is `reserved_name`, with the
reason in `delegation.error`. Its records are still looked up and
reported, but they are the resolver's own (Unbound answers `localhost` with
127.0.0.1 and ::1), so no address is probed and the warning is the only
finding apart from the resolver's reachability and the run deadline. The warning (until 2026-10-06 an `info`)
keeps the report from reading as a clean bill of health; `ok` stays true,
since nothing about the name is broken, only out of reach. The suffixes are
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
