# dog captures

Every file here is verbatim `dog -J -Z ad --timeout N -n <server> -q <name> -t <type>`
output (dog 1b5845d, the DataPulse fork the workers build), captured on 2026-10-07.
They replaced the delv captures when domaintest moved its lookups to dog.

The server is a validating Unbound 1.13.1 (Ubuntu 22.04) running the playwright
worker's `unbound-local.conf` on 127.0.0.1:8053, the resolver domaintest uses in
production, except:

- `google_a_unsigned.json`, `google_aaaa_unsigned.json`: 1.1.1.1 (validating).
  From the test host Unbound got six A and four AAAA for google.com; the web
  scenarios map one address per family, as the earlier captures had.
- `timeout.json`: 192.0.2.1 (TEST-NET-1, nothing answers) with `--timeout 1`,
  dog's real output for a query that got no response.
- `root_ns_v6_refused.json`: `[::1]:9` (nothing listens), dog's real output for
  a refused connection.

File names were kept from the delv captures they replace, so a few describe
the state at that time rather than now: `reserved/localtest_aaaa.json` now has
an AAAA record, and `outlook_host_txt_failure.json` is a real SERVFAIL.

`reserved/localhost_*.json` and `reserved/www_localhost_*.json` are Unbound's
answers from its built-in `localhost` local zone, which delv never let
through: they are what a reserved name looks like through the resolver.

Captured from 1.1.1.1 (validating) on 2026-10-07, for the review of the osu.edu
report: `mail/txt_osu_edu.json` (35 TXT records, a 360-byte SPF string; `dig +tcp
+noedns` measures the answer at 2813 octets), `mail/dkim_selector1_osu_edu.json`
(a CNAME to an RSA-1024 key at onmicrosoft.com), `mail/dkim_selector2_osu_edu_dangling.json`
(a CNAME whose target is NXDOMAIN), `mail/dkim_s1_github_com.json` (RSA-2048) and
`caa/osu_edu_none.json` (no CAA). `caa/jschmidt.json` was `caa/jschmidt_none.json`
until jschmidt.org was found to publish two CAA records when it was re-captured.
