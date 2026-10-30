# rdap captures

Every `<name>.stdout` / `<name>.stderr` pair is the verbatim output of one run
of openrdap's `rdap` CLI, built from upstream commit 64c8c7d (the commit the
scrape workers build), captured on 2026-10-29 from a residential host:

```
rdap --json --timeout 5 -- <domain>
rdap --json --timeout 5 -- <registrar URL>    # the *-registrar captures
```

| capture | what it shows |
|---|---|
| `google.com` | Verisign .com: six lock statuses, a `related` link to MarkMonitor |
| `google.com-registrar` | MarkMonitor's record, the same six statuses |
| `finalthreadss.com`, `-registrar` | `client hold` at Verisign and at Tucows |
| `3pattifacebook.site`, `-registrar` | `server hold` at Radix; GoDaddy's record has no hold, and serves non-standard values (`delete prohibited`) |
| `skvr.site-registrar` | GoDaddy, the same non-standard values |
| `datapulse.vip`, `-registrar` | `pending delete` and `redemption period` at the registry and at Namecheap |
| `loginmicrosoftonline.cloud` | `inactive` with `client hold` |
| `www.gov.uk` | Nominet: `inactive` for a name registered inside gov.uk and never delegated; no `related` link |
| `example.cz` | CZ.NIC: names the registrar, links to no registrar service |
| `microsoft.jp.net` | run with `-s https://rdap.centralnic.com/jp.net/` (dpdomain's private-suffix route); links to GMO's registrar service |
| `nonexist` | `datapulse-nonexistent-7f3a9c.com`: the registry's 404, exit 1 |
| `microsoftskype.net` | a 404 for a name portdb recorded in `redemptionPeriod` the same day |
| `de` | `denic.de`: no RDAP service for .de in the IANA bootstrap, exit 1 |
| `timeout` | `--timeout 1 -s https://10.255.255.1/` (nothing answers): the CLI's own timeout message, exit 1 |

The held and deleting domains were taken from portdb's `domain_registration`
statuses for that day. Registries change these records daily, so a fresh
capture of the same name can differ.
