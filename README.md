# dnsrustcon

A DNS and subdomain reconnaissance CLI written in Rust. Give it one or more targets (a domain, an IP address, or a CIDR block, auto-detected) and it enumerates subdomains, resolves the common DNS record types, enriches each resolved IP, and, in its active modes, brute forces names and attempts zone transfers.

## Features

- Subdomain enumeration from 16 discovery sources, run concurrently.
- Resolution of A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, and CAA records, plus PTR via reverse lookups.
- Per-IP enrichment: ASN, ASN name, RIR, announced prefix, and country from Team Cymru; registered organization from RDAP; open services from Shodan when a key is configured.
- Recursive brute force with a bundled wordlist, and AXFR zone-transfer attempts, in active and both modes.
- Wildcard filtering, including wildcard CNAMEs, so wildcard addresses are never reported or enriched.
- Optional passes: altdns-style permutations (`--permutations`), subdomain-takeover detection (`--takeover`), HTTP/TLS probing (`--probe`), and reverse/ASN neighbor sweeps (`--reverse`, `--sweep-prefix`).
- Scope confinement to the target domains, with `--out-of-scope` to keep co-listed names.
- Resume from a prior JSON export (`--resume`) so a re-run surfaces only new findings.
- Rate limiting (`--rate-limit`) applied to both DNS queries and HTTP sources, and custom resolvers (`--resolvers`) that are health-checked before use.
- Output as a terminal summary, JSON, CSV, or newline-delimited JSON.

## Installation

Requires Rust 1.88 or newer (see `rust-version` in `Cargo.toml`).

Build from source:

```bash
cargo build --release
```

The binary is written to `target/release/dnsrustcon`.

Install it onto your `PATH`:

```bash
cargo install --path .
```

Prebuilt binaries will be published on the GitHub Releases page.

## Usage

Passive scan of a domain (the default mode):

```bash
dnsrustcon example.com
```

Active and passive scan with a custom wordlist, recursing two levels deep:

```bash
dnsrustcon example.com --mode both -w words.txt --depth 2
```

Keyless passive scan with brute force excluded:

```bash
dnsrustcon example.com --exclude-sources bruteforce
```

Enumerate, then check for dangling takeovers and probe every host over HTTP(S):

```bash
dnsrustcon example.com --mode both --takeover --probe
```

Enrich a single IP address:

```bash
dnsrustcon 192.0.2.125
```

Write all output formats into a directory:

```bash
dnsrustcon example.com --output-dir results/
```

## Modes

Set the mode with `--mode` (default `passive`):

- `passive` queries the OSINT sources and resolves what they return. No brute forcing.
- `active` runs a depth-limited recursive brute force and attempts an AXFR zone transfer against each authoritative name server.
- `both` runs passive and active together.

PTR and ASN enrichment run in every mode, for every IP the engine processes, including explicit IP and CIDR targets. Enrichment is not tied to a mode. The neighbor sweep (`--reverse`) is a separate opt-in step.

In active and both modes the engine resolves the apex NS records and attempts a full AXFR against each. A transfer is almost always refused, but a misconfigured server occasionally returns the entire zone. Every dumped record is recorded, its owner name is queued as a discovered host, and address values are enriched like any other IP.

## Discovery sources

By default every discovery source runs. Narrow the set with `--sources` (run only those named) or `--exclude-sources` (run all but those named). The two flags are mutually exclusive, matching is case-insensitive, and an unknown name is rejected up front with the list of valid names. These flags affect only subdomain discovery, not the Shodan or RDAP IP-enrichment providers and not the AXFR attempt.

The valid source names are `crt.sh`, `hackertarget`, `otx`, `anubis`, `certspotter`, `wayback`, `bruteforce`, `securitytrails`, `virustotal`, `shodandns`, `chaos`, `dnsdumpster`, `censys`, `rapiddns`, `subdomaincenter`, and `urlscan`.

### Keyless

These work with no API key and run automatically:

- `crt.sh` (certificate transparency)
- `hackertarget` (host search)
- `otx` (AlienVault OTX passive DNS)
- `anubis` (jldc.me subdomain database)
- `certspotter` (certificate transparency)
- `wayback` (host names mined from archived URLs)
- `rapiddns` (host names from the subdomain export page)
- `subdomaincenter` (subdomain.center passive dataset)
- `urlscan` (host names mined from public page scans)
- `bruteforce` (wordlist brute force, active and both modes)

IP enrichment and resolution also work without keys: Team Cymru for ASN, ASN name, prefix, and country; RDAP for the registered organization; and DNS resolution itself.

### Keyed

These run only when their key is configured, and a failed call is non-fatal; the run continues with whatever the keyless sources returned.

- `securitytrails` (passive DNS subdomains)
- `virustotal` (passive DNS subdomains)
- `shodandns` (Shodan DNS subdomain listing; reuses the Shodan key)
- `chaos` (ProjectDiscovery Chaos dataset)
- `dnsdumpster` (host names from DnsDumpster A, CNAME, MX, and NS records)
- `censys` (certificate names from Censys certificate search)

Shodan also enriches each resolved IP with its open services when a key is present, populating the Services column of the IP table. This is enrichment, not a discovery source, so it is not affected by `--sources`.

## Configuration

API keys and a resolver list are read from environment variables or a config file. An environment variable takes precedence over the same key in the file.

Environment variables:

- `DNSRUSTCON_SHODAN_KEY` (also used by the `shodandns` source)
- `DNSRUSTCON_SECURITYTRAILS_KEY`
- `DNSRUSTCON_VIRUSTOTAL_KEY`
- `DNSRUSTCON_CHAOS_KEY`
- `DNSRUSTCON_DNSDUMPSTER_KEY`
- `DNSRUSTCON_CENSYS_API_ID`
- `DNSRUSTCON_CENSYS_API_SECRET`

The config file path comes from the OS config directory and differs by platform:

- Linux: `~/.config/dnsrustcon/config.toml`
- macOS: `~/Library/Application Support/dnsrustcon/config.toml`
- Windows: `%APPDATA%\dnsrustcon\config.toml`

Point at a file elsewhere with `--config <path>`. The file format:

```toml
shodan_key = "..."
securitytrails_key = "..."
virustotal_key = "..."
chaos_key = "..."
dnsdumpster_key = "..."
censys_api_id = "..."
censys_api_secret = "..."
resolvers = ["1.1.1.1", "8.8.8.8"]
```

Shodan's API requires the key as a URL query parameter, so it can appear in proxy and server access logs. SecurityTrails and VirusTotal send their keys in a request header, which keeps them out of those logs.

Custom resolvers can also be passed with `--resolvers`, as an inline comma-separated list or a path to a file with one resolver per line. When given, it replaces the resolver list from the config file. Any custom resolver list is health-checked before use: each resolver is queried for a known-good name and for a random name under `.invalid` that can never exist, and a resolver that fails the good lookup or answers the bogus one (an NXDOMAIN hijacker) is dropped. If none pass, the tool warns and proceeds with the list unvalidated. The system default resolver skips this check.

## Output formats

By default dnsrustcon prints only the end-of-run summary. It opens with the SUBDOMAINS section (or the scan-parameter line under `-v`), prints each DNS record type in its own count-labeled block, and shows an IP table with columns IP, ASN, ASN Name, RIR, Org, PTR, Prefix, Country, and Services. A successful transfer adds a ZONE TRANSFER section, `--takeover` always adds a SUBDOMAIN TAKEOVER section that states the result either way, and `--probe` adds an HTTP/TLS PROBES section.

Verbosity has three levels:

- `-q`/`--quiet`: the summary only, with no live stream and no progress spinner.
- default: the summary, a progress spinner on stderr, and high-signal live alerts such as a zone transfer or takeover.
- `-v`/`--verbose`: the full live finding stream on stdout, the scan-parameter header, and source diagnostics on stderr (which sources ran, which were skipped and why, and any provider errors).

Use `--no-color` to disable coloring. The progress spinner draws to stderr and is suppressed when stderr is not a terminal, so it never mixes into the finding stream or the exports.

Findings can also be exported:

- `--json <FILE>` writes the full result (hosts, records, IP enrichment, takeovers, zone transfers, and probes) as structured JSON.
- `--csv <FILE>` writes the same result as a name, type, value table, one row per host, record, IP, takeover, zone transfer, and probe.
- `--jsonl <FILE>` streams one compact JSON object per finding as it is discovered, flushed so it can be tailed live. Each line carries a `kind` field: `host`, `record`, `ip`, `takeover`, `zone_transfer`, or `probe`.
- `--output-dir <DIR>` writes all three formats (`dnsrustcon.json`, `dnsrustcon.csv`, `dnsrustcon.txt`) into one directory, creating it if needed. This is additive to `--json` and `--csv`.

## Selected behavior

A few passes are worth calling out.

Wildcard filtering. When an apex has a wildcard record, every name appears to resolve to the same address. dnsrustcon probes a random name under the apex, records the wildcard address set, and suppresses any A/AAAA record whose value is in that set. During brute force each base name is also checked for its own wildcard, including wildcard CNAMEs.

Scope. For a domain target, a discovered name is kept only if it falls under one of the scanned domains. OSINT sources routinely surface unrelated names, such as a second company's domain co-listed on a shared certificate; those are dropped rather than resolved. Pass `--out-of-scope` to keep them. Explicit IP and CIDR targets are unaffected.

Takeover detection. `--takeover` inspects every host with a CNAME to a takeover-prone service, across 18 services. A host is flagged only with concrete evidence: either the CNAME target no longer resolves, or an HTTP fetch returns the service's documented unclaimed-resource marker. Marker findings go through a second fetch and must show the marker on two independent responses, the confirming one carrying an HTTP error status. Findings are reported as potential takeovers.

Probing. `--probe` fingerprints each discovered host over HTTP(S) after discovery finishes. For each host it tries `https://` then `http://`, records the status code, page title, and final URL after redirects, and opens a TLS connection to port 443 to collect the leaf certificate SAN dNSName entries. The pass is non-fatal: a host that does not answer yields a partial or empty probe rather than aborting the run.

Reverse sweeps. PTR and ASN enrichment run for every IP regardless of any flag. `--reverse` adds a neighbor sweep for domain targets: it also sweeps the containing /24 of each resolved IPv4 address. `--sweep-prefix` widens that sweep to the ASN-announced prefix, falling back to the /24 if the prefix is missing or would exceed the 65536-host cap (unless `--allow-large-sweep` is given).

Inactive domains. A domain with no NS or SOA record is skipped.

## Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `targets` (positional) | | required | One or more domains, IPs, or CIDR blocks |
| `--mode` | | `passive` | Scan mode: `passive`, `active`, or `both` |
| `--wordlist` | `-w` | bundled list | Wordlist file for `active`/`both`; optional, falls back to the bundled 5,000-label list. Repeatable to merge several lists |
| `--permutations` | | off | In `active`/`both`, run an altdns-style permutation pass over discovered hosts using the wordlist(s) |
| `--out-of-scope` | | off | Keep hosts discovered outside the target domain(s); by default such names are dropped |
| `--takeover` | | off | Check hosts with a CNAME to a takeover-prone service for a dangling target; the summary states the result either way |
| `--probe` | | off | Probe each discovered host over HTTP(S) for status code, page title, final URL, and TLS certificate SAN names |
| `--depth` | `-d` | `2` | Recursive brute-force depth |
| `--record-types` | | all types | Comma-separated record types to query (default is all) |
| `--sources` | | all sources | Run only these discovery sources (comma-separated, case-insensitive). Mutually exclusive with `--exclude-sources` |
| `--exclude-sources` | | none | Run every discovery source except these (comma-separated, case-insensitive). Mutually exclusive with `--sources` |
| `--reverse` | | off | Enable the neighbor sweep for domain targets: also sweep the containing /24 of each resolved IPv4 (or the ASN prefix with `--sweep-prefix`) |
| `--sweep-prefix` | | off | With `--reverse` on a domain target, widen the neighbor sweep from the /24 to the IP's ASN-announced prefix, subject to the sweep cap unless `--allow-large-sweep` is given |
| `--allow-large-sweep` | | off | Allow a CIDR target or ASN prefix larger than 65536 hosts to be swept; without it such a target is rejected |
| `--resolvers` | | system default | Custom resolvers: a file path or an inline comma-separated list |
| `--concurrency` | `-t` | `50` | Maximum concurrent lookups |
| `--timeout` | | `5` | DNS query timeout in seconds |
| `--rate-limit` | | none | Throttle DNS queries and HTTP sources to at most this many per second |
| `--json` | | none | Write the full result to this path as JSON |
| `--csv` | | none | Write the full result to this path as CSV |
| `--output-dir` | | none | Write all three formats (`dnsrustcon.json`, `dnsrustcon.csv`, `dnsrustcon.txt`) into this directory; additive to `--json`/`--csv` |
| `--jsonl` | | none | Stream findings to this file as newline-delimited JSON, one object per finding, as they are discovered |
| `--resume` | | none | Read a prior `--json` export and skip hosts already listed in it, so the run only surfaces new findings |
| `--config` | | OS config dir | Path to a config file |
| `--quiet` | `-q` | off | Print only the end-of-run summary: suppress the live stream and the progress spinner |
| `--verbose` | `-v` | off | Stream each finding live, show the scan-parameter header, and print source diagnostics on stderr |
| `--no-color` | | off | Disable colored output |

## Authorized use

This tool performs active reconnaissance against the systems you point it at, including brute-force queries, zone-transfer attempts, and HTTP probing. Use it only against systems you own or have explicit, written authorization to test. You are responsible for complying with all applicable laws and with the terms of service of any third-party data source or resolver you query. Unauthorized scanning may be illegal.

## License

Released under the MIT License. See the LICENSE file for details.
