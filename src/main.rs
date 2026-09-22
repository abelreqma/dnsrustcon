#![forbid(unsafe_code)]

mod cli;
mod config;
mod engine;
mod model;
mod output;
mod probe;
mod resolve;
mod sources;
mod takeover;

use anyhow::Context as _;
use clap::Parser;
use engine::{FeatureOpts, SweepOpts};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Cli::parse();
    args.validate()?;
    let cfg = config::Config::load(&args)?;

    let targets: Vec<model::Target> = args
        .targets
        .iter()
        .map(|t| model::Target::parse(t))
        .collect::<Result<_, _>>()?;

    // Guard against enumerating an oversized CIDR (a large IPv4 block or any
    // IPv6 block). Fail fast unless the user opted in with --allow-large-sweep.
    if !args.allow_large_sweep {
        for t in &targets {
            if let model::Target::Cidr(net) = t {
                let over_cap = match sources::reverse::sweep_host_count(net) {
                    Some(count) => count > sources::reverse::MAX_SWEEP_HOSTS,
                    None => true,
                };
                if over_cap {
                    anyhow::bail!(
                        "CIDR {} would sweep more than {} hosts; narrow the range or pass --allow-large-sweep",
                        net,
                        sources::reverse::MAX_SWEEP_HOSTS
                    );
                }
            }
        }
    }

    let mut record_types = match &args.record_types {
        Some(list) => list
            .split(',')
            .map(|s| s.trim().parse::<model::RecordType>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!(e))?,
        None => model::RecordType::all(),
    };
    // Takeover detection reads CNAME records, so ensure CNAME is queried even if
    // the user narrowed --record-types.
    if args.takeover && !record_types.contains(&model::RecordType::Cname) {
        record_types.push(model::RecordType::Cname);
    }

    // Merge every -w wordlist into one deduplicated list, preserving first-seen
    // order across files. With no -w given, fall back to the wordlist bundled
    // into the binary so active/both mode works out of the box.
    let words = {
        let mut seen = std::collections::HashSet::new();
        let mut all = Vec::new();
        if args.wordlist.is_empty() {
            for w in sources::bruteforce::default_words() {
                if seen.insert(w.clone()) {
                    all.push(w);
                }
            }
        } else {
            for p in &args.wordlist {
                for w in sources::bruteforce::load_wordlist(p)? {
                    if seen.insert(w.clone()) {
                        all.push(w);
                    }
                }
            }
        }
        all
    };

    // User-supplied resolvers are health-checked before use: a poisoned or dead
    // resolver would silently corrupt every lookup. Survivors replace the list;
    // if none pass we fail open (warn and use them anyway) so a restricted
    // network cannot brick the run. The system default (empty list) is trusted
    // and skips validation.
    let resolvers = if cfg.resolvers.is_empty() {
        Vec::new()
    } else {
        let healthy = resolve::validate_resolvers(&cfg.resolvers, args.timeout).await;
        if healthy.is_empty() {
            eprintln!(
                "warning: none of the {} configured resolver(s) passed health validation; proceeding with them unvalidated",
                cfg.resolvers.len()
            );
            cfg.resolvers.clone()
        } else {
            if args.verbose && healthy.len() != cfg.resolvers.len() {
                eprintln!(
                    "[verbose] {}/{} resolvers passed validation",
                    healthy.len(),
                    cfg.resolvers.len()
                );
            }
            healthy
        }
    };

    // Apply the same --rate-limit cap to the HTTP OSINT sources, not just DNS,
    // so a shared per-second budget throttles every outbound request.
    sources::init_http_rate_limit(args.rate_limit);

    let resolver = Arc::new(resolve::HickoryResolver::new(
        &resolvers,
        args.timeout,
        args.rate_limit,
    )?);

    // Shodan supplies open-service data through IP enrichment, not the
    // candidate channel, so it is a ServiceProvider handed to the engine rather
    // than a Source. Built only when a key is configured.
    let shodan: Option<Arc<dyn resolve::enrich::ServiceProvider>> =
        cfg.shodan_key.clone().map(|k| {
            Arc::new(sources::shodan::ShodanClient { key: k })
                as Arc<dyn resolve::enrich::ServiceProvider>
        });

    // RDAP network-registration enrichment is keyless, so it is always on. It
    // is an OrgProvider handed to the engine (like Shodan's ServiceProvider),
    // populating IpInfo.org for every enriched IP.
    let rdap: Option<Arc<dyn resolve::enrich::OrgProvider>> = match sources::rdap::RdapClient::new()
    {
        Ok(c) => Some(Arc::new(c) as Arc<dyn resolve::enrich::OrgProvider>),
        Err(_) => None,
    };

    let mut sources: Vec<Box<dyn sources::Source>> = vec![
        Box::new(sources::crtsh::CrtSh),
        Box::new(sources::hackertarget::HackerTarget),
        Box::new(sources::otx::Otx),
        Box::new(sources::anubis::Anubis),
        Box::new(sources::certspotter::CertSpotter),
        Box::new(sources::wayback::Wayback),
        Box::new(sources::rapiddns::RapidDns),
        Box::new(sources::subdomaincenter::SubdomainCenter),
        Box::new(sources::urlscan::UrlScan),
        Box::new(sources::bruteforce::BruteForce {
            words: words.clone(),
        }),
    ];
    // Keyed sources are always registered, even without a key: constructed
    // with an empty key their available() returns false, so the engine emits a
    // "no key" SourceSkipped event (surfaced under -v) instead of the source
    // silently never existing.
    sources.push(Box::new(sources::passivedns::SecurityTrails {
        key: cfg.securitytrails_key.clone().unwrap_or_default(),
    }));
    sources.push(Box::new(sources::virustotal::VirusTotal {
        key: cfg.virustotal_key.clone().unwrap_or_default(),
    }));
    // shodandns reuses the existing Shodan key.
    sources.push(Box::new(sources::shodandns::ShodanDns {
        key: cfg.shodan_key.clone().unwrap_or_default(),
    }));
    sources.push(Box::new(sources::chaos::Chaos {
        key: cfg.chaos_key.clone().unwrap_or_default(),
    }));
    sources.push(Box::new(sources::dnsdumpster::DnsDumpster {
        key: cfg.dnsdumpster_key.clone().unwrap_or_default(),
    }));
    sources.push(Box::new(sources::censys::Censys {
        api_id: cfg.censys_api_id.clone().unwrap_or_default(),
        api_secret: cfg.censys_api_secret.clone().unwrap_or_default(),
    }));

    // Restrict the discovery sources to what --sources / --exclude-sources
    // select (the two flags are mutually exclusive, enforced in validate). This
    // touches only the candidate-emitting Sources; the Shodan/RDAP IP-enrichment
    // providers and the engine-internal AXFR step are unaffected.
    let source_filter = if let Some(list) = &args.sources {
        sources::SourceFilter::Only(sources::parse_source_list(list)?)
    } else if let Some(list) = &args.exclude_sources {
        sources::SourceFilter::Exclude(sources::parse_source_list(list)?)
    } else {
        sources::SourceFilter::All
    };
    sources::apply_source_filter(&mut sources, &source_filter);

    // With --resume, load the hosts array from a prior --json export and treat
    // those hosts as already known so the engine skips them entirely.
    let known_hosts: std::collections::HashSet<String> = match &args.resume {
        Some(p) => {
            let data = std::fs::read_to_string(p)
                .with_context(|| format!("failed to read --resume file {}", p.display()))?;
            let parsed: serde_json::Value = serde_json::from_str(&data).with_context(|| {
                format!("failed to parse --resume file {} as JSON", p.display())
            })?;
            let hosts = parsed
                .get("hosts")
                .and_then(|h| h.as_array())
                .ok_or_else(|| {
                    anyhow::anyhow!("--resume file {} has no hosts array", p.display())
                })?;
            hosts
                .iter()
                .filter_map(|v| v.as_str())
                .map(model::normalize_host)
                .collect()
        }
        None => std::collections::HashSet::new(),
    };

    let opts = engine::EngineOpts {
        depth: args.depth,
        concurrency: args.concurrency,
        record_types,
        words,
        scope: !args.out_of_scope,
        sweep: SweepOpts {
            reverse: args.reverse,
            sweep_prefix: args.sweep_prefix,
            allow_large_sweep: args.allow_large_sweep,
        },
        features: FeatureOpts {
            permutations: args.permutations,
            takeover: args.takeover,
            probe: args.probe,
        },
        known_hosts,
    };
    let mut eng = engine::Engine::new(args.mode, resolver, sources, cfg, opts, shodan, rdap);

    // A spinner on stderr tracks the current phase and a running count of
    // completed lookups. It draws to stderr so it never mixes into stdout
    // findings or the --json/--csv exports; findings are printed through
    // pb.suspend so the live stream and the bar do not clobber each other.
    let progress = indicatif::ProgressBar::new_spinner();
    progress.set_style(
        indicatif::ProgressStyle::with_template("{spinner:.green} {msg} [{pos} done]")
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_spinner()),
    );
    // Under --quiet the spinner is hidden so nothing but the final summary is
    // emitted; the engine and printer still hold the bar and advance it harmlessly.
    if args.quiet {
        progress.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    }
    progress.enable_steady_tick(std::time::Duration::from_millis(120));
    eng.set_progress(progress.clone());

    let printer = output::Printer {
        color: !args.no_color,
        quiet: args.quiet,
        verbose: args.verbose,
        progress: Some(progress.clone()),
    };
    // With --jsonl, open the streaming file up front (fail fast on a bad path)
    // so the sink can append one compact JSON line per finding as it is found.
    let mut jsonl_writer = match &args.jsonl {
        Some(p) => Some(std::io::BufWriter::new(
            std::fs::File::create(p)
                .with_context(|| format!("failed to open --jsonl file {}", p.display()))?,
        )),
        None => None,
    };

    let start = std::time::Instant::now();
    let findings = eng
        .run(&targets, &mut |e| {
            printer.event(&e);
            if let Some(w) = jsonl_writer.as_mut() {
                if let Some(line) = output::export::event_to_jsonl(&e) {
                    use std::io::Write as _;
                    let _ = writeln!(w, "{line}");
                    let _ = w.flush();
                }
            }
        })
        .await;
    let elapsed = start.elapsed().as_secs_f64();
    progress.finish_and_clear();
    let mode = format!("{:?}", args.mode).to_lowercase();
    let target_label = args.targets.join(", ");
    printer.summary(
        &findings,
        &target_label,
        &mode,
        args.depth,
        elapsed,
        args.takeover,
    );

    if let Some(p) = &args.json {
        std::fs::write(p, output::export::to_json(&findings)?)?;
    }
    if let Some(p) = &args.csv {
        output::export::write_csv(&findings, p)?;
    }

    // --output-dir writes all three formats into one directory. It is additive
    // to --json/--csv: if those explicit paths were also given, they are still
    // honored above.
    if let Some(dir) = &args.output_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create --output-dir {}", dir.display()))?;
        std::fs::write(
            dir.join("dnsrustcon.json"),
            output::export::to_json(&findings)?,
        )?;
        output::export::write_csv(&findings, &dir.join("dnsrustcon.csv"))?;
        std::fs::write(
            dir.join("dnsrustcon.txt"),
            output::render_report_plain(
                &findings,
                &target_label,
                &mode,
                args.depth,
                elapsed,
                true,
                args.takeover,
            ),
        )?;
    }
    Ok(())
}
