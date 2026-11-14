mod bootstrap;
mod bulk;
mod ctx;
mod lookup;
mod mcp;
mod model;
mod normalize;
mod output;
mod query;
mod rdap;
mod sanitize;
mod watch;
mod whois43;

use clap::{Args, Parser, Subcommand, ValueEnum};
use ctx::{Ctx, Options};
use futures::StreamExt;
use model::Outcome;
use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

/// Exit codes (stable, for scripts and agents).
mod exit {
    pub const OK: i32 = 0;
    pub const FAILED: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const NOT_FOUND: i32 = 10;
}

#[derive(Parser)]
#[command(
    name = "whoq",
    version,
    about = "RDAP-first WHOIS for humans and agents",
    long_about = "RDAP-first WHOIS for humans and agents.\n\n\
Looks up domains, IPs, CIDRs and ASNs via RDAP (IANA bootstrap), falling back to port-43 WHOIS.\n\
Accepts URLs and emails. Pretty output on a TTY, NDJSON when piped.",
    after_help = "EXIT CODES:\n  0   all lookups found/registered\n  1   at least one lookup failed\n  2   usage error\n  10  at least one domain available / object not found\n\n\
EXAMPLES:\n  whoq example.com\n  whoq watch mydomain.com      # change & expiry alerts\n  whoq bulk -m summary < access.log   # who is hitting you\n  whoq https://www.bbc.co.uk/news 8.8.8.8 AS13335\n  whoq -b -f expires,signals.expires_in_days example.com\n  cat domains.txt | whoq -o ndjson\n  whoq mcp        # run as an MCP server",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    lookup: LookupArgs,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run as an MCP server on stdio (tools: lookup, check_availability)
    Mcp(CommonArgs),
    /// Snapshot records and report changes since the last run (hijack, expiry, drop alerts)
    Watch(WatchArgs),
    /// Enrich IPs in logs with ASN / owner data (Team Cymru + optional RDAP, network-deduped)
    Bulk(BulkArgs),
    /// Print the JSON Schema for output records
    Schema,
}

#[derive(Copy, Clone, PartialEq, ValueEnum)]
enum BulkMode {
    /// One output row per input line, with its IPs enriched
    Annotate,
    /// One row per distinct IP, with hit counts
    Unique,
    /// Hits grouped by ASN / owner
    Summary,
}

#[derive(Copy, Clone, PartialEq, ValueEnum)]
enum BulkFormat {
    Auto,
    Ndjson,
    /// annotate: original line + tab-separated columns (ip, asn, as_name, country, prefix, org)
    Tsv,
    /// unique / summary: CSV with header
    Csv,
    /// table (unique / summary)
    Pretty,
}

#[derive(Args)]
#[command(after_help = "SOURCES:\n  Default: Team Cymru IP-to-ASN bulk whois (whois.cymru.com) — ASN, AS name, BGP prefix, country.\n  --rdap adds registry org, network name and abuse contact (one request per network, not per IP).\n  Private/reserved IPs are never sent anywhere.\n\n\
EXAMPLES:\n  tail -n 100000 access.log | whoq bulk -m summary\n  whoq bulk -f 1 -o tsv access.log > enriched.tsv\n  whoq bulk -m unique --rdap -o csv fw.log > owners.csv\n  zcat auth.log.gz | whoq bulk --rdap | jq -c 'select(.ips[].asn == 14061)'")]
struct BulkArgs {
    /// Log files to read (default: stdin). Literal IPs are accepted too.
    inputs: Vec<String>,
    /// Take IPs only from this 1-based field (default: scan the whole line)
    #[arg(short, long)]
    field: Option<usize>,
    /// Field delimiter for --field (default: whitespace)
    #[arg(short, long)]
    delim: Option<char>,
    #[arg(short, long, value_enum, default_value_t = BulkMode::Annotate)]
    mode: BulkMode,
    #[arg(short, long, value_enum, default_value_t = BulkFormat::Auto)]
    output: BulkFormat,
    /// Also query RDAP for org, network name and abuse contact
    #[arg(long)]
    rdap: bool,
    /// Skip Team Cymru (RDAP only; implies --rdap)
    #[arg(long)]
    no_cymru: bool,
    /// Don't reuse RDAP networks broader than /24 (v4) or /48 (v6)
    #[arg(long)]
    precise: bool,
    /// Rows to show in summary mode (0 = all)
    #[arg(long, default_value_t = 25)]
    top: usize,
    /// Parallel RDAP lookups
    #[arg(short = 'j', long, default_value_t = 8)]
    concurrency: usize,
    /// Network cache lifetime in days
    #[arg(long, default_value_t = 7)]
    cache_days: u64,
    /// Don't read or write the network cache
    #[arg(long)]
    no_cache: bool,
    #[arg(long, default_value_t = 30, env = "WHOQ_TIMEOUT")]
    timeout: u64,
    /// Suppress the stats line on stderr
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
#[command(after_help = "EXIT CODES (one-shot mode):\n  0   nothing changed\n  1   lookups failed and nothing changed\n  20  changes or alerts detected\n\n\
EXAMPLES:\n  whoq watch mydomain.com mybrand.net           # first run records a baseline\n  whoq watch -i 6h --webhook $SLACK_URL < domains.txt\n  0 */6 * * * whoq watch -q < ~/domains.txt || notify  # cron")]
struct WatchArgs {
    /// Domains, IPs or ASNs to watch. `-` (or piped stdin) reads one per line.
    queries: Vec<String>,
    /// Keep running, re-checking at this interval (e.g. 30m, 6h, 1d). Default: check once and exit.
    #[arg(short, long)]
    interval: Option<String>,
    /// Alert when a domain expires within this many days
    #[arg(long, default_value_t = 30)]
    expiry_warn: i64,
    /// POST actionable events as JSON ({text, events}) to this URL — Slack/Discord-style webhooks work
    #[arg(long, env = "WHOQ_WEBHOOK")]
    webhook: Option<String>,
    /// Ignore changes to these fields (dotted prefixes), e.g. `updated,registrant`
    #[arg(long, value_delimiter = ',')]
    ignore: Vec<String>,
    /// Also emit `unchanged` events
    #[arg(long)]
    all: bool,
    /// Only print actionable events (changes, alerts, errors)
    #[arg(short, long)]
    quiet: bool,
    /// Where snapshots live (default: OS data dir, or WHOQ_STATE_DIR)
    #[arg(long)]
    state: Option<std::path::PathBuf>,
    /// Output format (auto: pretty on a TTY, ndjson otherwise)
    #[arg(short, long, value_enum, default_value_t = Format::Auto)]
    output: Format,
    /// Parallel lookups
    #[arg(short = 'j', long, default_value_t = 4)]
    concurrency: usize,
    #[arg(long)]
    no_color: bool,
    #[arg(long, default_value_t = 15, env = "WHOQ_TIMEOUT")]
    timeout: u64,
}

#[derive(Args, Clone)]
struct CommonArgs {
    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 15, env = "WHOQ_TIMEOUT")]
    timeout: u64,
    /// Result cache TTL in seconds
    #[arg(long, default_value_t = 3600, env = "WHOQ_CACHE_TTL")]
    cache_ttl: u64,
    /// Don't read or write the result cache
    #[arg(long)]
    no_cache: bool,
}

#[derive(Copy, Clone, PartialEq, ValueEnum)]
enum Format {
    Auto,
    Pretty,
    Json,
    Ndjson,
}

#[derive(Args)]
struct LookupArgs {
    /// Domains, URLs, emails, IPs, CIDRs or ASNs. `-` (or no args with piped stdin) reads one per line.
    queries: Vec<String>,
    /// Output format (auto: pretty on a TTY, ndjson otherwise)
    #[arg(short, long, value_enum, default_value_t = Format::Auto)]
    output: Format,
    /// Shorthand for `-o json`
    #[arg(long)]
    json: bool,
    /// Only these dotted fields, e.g. `registrar.name,expires,signals`
    #[arg(short, long, value_delimiter = ',')]
    fields: Vec<String>,
    /// Compact summary (token-friendly)
    #[arg(short, long)]
    brief: bool,
    /// Include raw upstream responses
    #[arg(long)]
    raw: bool,
    /// Force legacy port-43 WHOIS for domains
    #[arg(long)]
    whois: bool,
    /// Parallel lookups
    #[arg(short = 'j', long, default_value_t = 8)]
    concurrency: usize,
    /// Disable colors (also honors NO_COLOR)
    #[arg(long)]
    no_color: bool,
    #[command(flatten)]
    common: CommonArgs,
}

fn options(c: &CommonArgs, raw: bool, force_whois: bool) -> Options {
    Options {
        timeout: Duration::from_secs(c.timeout.max(1)),
        cache_ttl: Duration::from_secs(c.cache_ttl),
        use_cache: !c.no_cache && c.cache_ttl > 0,
        raw,
        force_whois,
    }
}

fn fatal(json: bool, code: &str, msg: &str) -> ! {
    if json {
        eprintln!("{}", serde_json::json!({ "error": { "code": code, "message": msg } }));
    } else {
        eprintln!("whoq: {msg}");
    }
    std::process::exit(exit::USAGE)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Schema) => {
            let schema = schemars::schema_for!(model::Record);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap());
        }
        Some(Cmd::Mcp(c)) => {
            let ctx = Ctx::new(options(&c, false, false)).unwrap_or_else(|e| fatal(true, "init", &e.to_string()));
            if let Err(e) = mcp::serve(ctx).await {
                eprintln!("whoq mcp: {e}");
                std::process::exit(exit::FAILED);
            }
        }
        Some(Cmd::Watch(w)) => std::process::exit(run_watch(w).await),
        Some(Cmd::Bulk(b)) => std::process::exit(run_bulk(b).await),
        None => std::process::exit(run(cli.lookup).await),
    }
}

/// Args plus stdin (when `-` is given or stdin is piped). `#` starts a comment; commas/spaces separate.
fn read_queries(args: &[String]) -> Vec<String> {
    let mut queries: Vec<String> = args.iter().filter(|q| *q != "-").cloned().collect();
    let want_stdin = args.iter().any(|q| q == "-") || (args.is_empty() && !std::io::stdin().is_terminal());
    if want_stdin {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            let t = line.split('#').next().unwrap_or("").trim();
            if !t.is_empty() {
                queries.extend(t.split([',', ' ', '\t']).filter(|s| !s.is_empty()).map(str::to_string));
            }
        }
    }
    queries
}

async fn run_watch(w: WatchArgs) -> i32 {
    let tty = std::io::stdout().is_terminal();
    let pretty = matches!(w.output, Format::Pretty) || (w.output == Format::Auto && tty);
    let queries = read_queries(&w.queries);
    if queries.is_empty() {
        fatal(!pretty, "usage", "nothing to watch (try `whoq watch example.com`)");
    }
    let interval = w.interval.as_deref().map(|s| watch::parse_interval(s).unwrap_or_else(|e| fatal(!pretty, "usage", &e)));
    let dir = watch::state_dir(w.state.clone()).unwrap_or_else(|| fatal(!pretty, "state", "no state directory; pass --state"));
    // Watching always needs fresh data: never read the result cache.
    let opts = Options {
        timeout: Duration::from_secs(w.timeout.max(1)),
        cache_ttl: Duration::ZERO,
        use_cache: false,
        raw: false,
        force_whois: false,
    };
    let ctx = Ctx::new(opts).unwrap_or_else(|e| fatal(!pretty, "init", &e.to_string()));
    let style = output::Style { color: tty && !w.no_color && std::env::var_os("NO_COLOR").is_none() };
    let ropts = watch::RoundOpts { dir: &dir, ignore: &w.ignore, expiry_warn_days: w.expiry_warn, show_unchanged: w.all };

    loop {
        let mut stream = futures::stream::iter(queries.clone())
            .map(|q| {
                let ctx = ctx.clone();
                async move { lookup::lookup(&ctx, &q).await }
            })
            .buffered(w.concurrency.clamp(1, 32));
        let mut events = vec![];
        while let Some(rec) = stream.next().await {
            for ev in watch::process(rec, &ropts) {
                let show = !w.quiet || watch::is_actionable(&ev) || ev["event"] == "error";
                if show {
                    if pretty {
                        print!("{}", output::pretty_event(&ev, &style));
                    } else {
                        println!("{ev}");
                    }
                    let _ = std::io::stdout().flush();
                }
                events.push(ev);
            }
        }
        let actionable: Vec<_> = events.iter().filter(|e| watch::is_actionable(e)).cloned().collect();
        if pretty && !w.quiet {
            let errors = events.iter().filter(|e| e["event"] == "error").count();
            let line = format!(
                "{} watched · {} changed/alerts · {} errors{}",
                queries.len(),
                actionable.len(),
                errors,
                interval.map(|d| format!(" · next check in {}m", d.as_secs() / 60)).unwrap_or_default()
            );
            println!("{}", if style.color { format!("\x1b[2m{line}\x1b[0m") } else { line });
        }
        if let (Some(url), false) = (&w.webhook, actionable.is_empty()) {
            let body = serde_json::json!({ "text": watch::summary(&actionable), "events": actionable });
            match ctx.http.post(url).json(&body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => eprintln!("whoq watch: webhook returned HTTP {}", r.status()),
                Err(e) => eprintln!("whoq watch: webhook failed: {e}"),
            }
        }
        match interval {
            Some(d) => tokio::time::sleep(d).await,
            None => {
                return if !actionable.is_empty() {
                    20
                } else if events.iter().any(|e| e["event"] == "error") {
                    exit::FAILED
                } else {
                    exit::OK
                };
            }
        }
    }
}

const BULK_CHUNK: usize = 5000;

fn bulk_input(inputs: &[String]) -> Box<dyn Iterator<Item = String>> {
    if inputs.is_empty() || inputs == ["-"] {
        return Box::new(std::io::stdin().lines().map_while(Result::ok));
    }
    let mut its: Vec<Box<dyn Iterator<Item = String>>> = vec![];
    for i in inputs {
        if i == "-" {
            its.push(Box::new(std::io::stdin().lines().map_while(Result::ok)));
        } else if std::path::Path::new(i).is_file() {
            match std::fs::File::open(i) {
                Ok(f) => its.push(Box::new(std::io::BufReader::new(f).lines().map_while(Result::ok))),
                Err(e) => fatal(false, "usage", &format!("{i}: {e}")),
            }
        } else if i.parse::<std::net::IpAddr>().is_ok() {
            its.push(Box::new(std::iter::once(i.clone())));
        } else {
            fatal(false, "usage", &format!("{i}: not a file or IP address"));
        }
    }
    Box::new(its.into_iter().flatten())
}

fn tsv_cols(o: Option<&bulk::Owner>) -> String {
    let Some(o) = o else { return "\t\t\t\t\t".into() };
    let c = |s: &Option<String>| s.as_deref().unwrap_or("").replace('\t', " ");
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        o.ip,
        o.asn.map(|a| format!("AS{a}")).unwrap_or_else(|| if o.private { "private".into() } else { String::new() }),
        c(&o.as_name),
        c(&o.country),
        c(&o.prefix),
        c(&o.org)
    )
}

async fn run_bulk(b: BulkArgs) -> i32 {
    if b.field == Some(0) {
        fatal(false, "usage", "--field is 1-based");
    }
    let tty = std::io::stdout().is_terminal();
    let format = match (b.output, b.mode) {
        (BulkFormat::Auto, BulkMode::Annotate) => BulkFormat::Ndjson,
        (BulkFormat::Auto, _) if tty => BulkFormat::Pretty,
        (BulkFormat::Auto, _) => BulkFormat::Ndjson,
        (f, _) => f,
    };
    match (format, b.mode) {
        (BulkFormat::Tsv, BulkMode::Annotate) | (BulkFormat::Ndjson, _) => {}
        (BulkFormat::Tsv, _) => fatal(false, "usage", "-o tsv is for annotate mode; use -o csv"),
        (_, BulkMode::Annotate) => fatal(false, "usage", "annotate mode supports -o ndjson or -o tsv"),
        _ => {}
    }
    let opts = Options {
        timeout: Duration::from_secs(b.timeout.max(1)),
        cache_ttl: Duration::ZERO,
        use_cache: false, // per-IP record files would explode; the engine has its own network cache
        raw: false,
        force_whois: false,
    };
    let ctx = Ctx::new(opts).unwrap_or_else(|e| fatal(true, "init", &e.to_string()));
    let engine = bulk::Engine::new(
        ctx,
        bulk::EngineOpts {
            cymru: !b.no_cymru,
            rdap: b.rdap || b.no_cymru,
            precise: b.precise,
            persist: !b.no_cache,
            cache_ttl: Duration::from_secs(b.cache_days * 86400),
            concurrency: b.concurrency,
        },
    );

    let started = std::time::Instant::now();
    let mut lines_in = bulk_input(&b.inputs);
    let mut seen: std::collections::HashMap<std::net::IpAddr, (bulk::Owner, usize)> = Default::default();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let mut total_lines = 0usize;
    let mut failed = false;

    loop {
        let chunk: Vec<String> = lines_in.by_ref().take(BULK_CHUNK).collect();
        if chunk.is_empty() {
            break;
        }
        total_lines += chunk.len();
        let per_line: Vec<Vec<std::net::IpAddr>> = chunk
            .iter()
            .map(|l| match b.field {
                Some(f) => bulk::extract_field(l, f, b.delim),
                None => bulk::extract(l),
            })
            .collect();
        let uniq: std::collections::HashSet<_> = per_line.iter().flatten().copied().collect();
        let owners = engine.resolve(&uniq).await;
        engine.flush();
        failed |= owners.values().any(|o| o.error.is_some());

        for (line, ips) in chunk.iter().zip(&per_line) {
            for ip in ips {
                let e = seen.entry(*ip).or_insert_with(|| (owners[ip].clone(), 0));
                e.1 += 1;
            }
            if b.mode == BulkMode::Annotate {
                let r = if format == BulkFormat::Tsv {
                    writeln!(out, "{line}\t{}", tsv_cols(ips.first().map(|i| &owners[i])))
                } else {
                    let enriched: Vec<&bulk::Owner> = ips.iter().map(|i| &owners[i]).collect();
                    writeln!(out, "{}", serde_json::json!({ "line": line, "ips": enriched }))
                };
                if r.is_err() {
                    return exit::OK; // downstream closed (e.g. `| head`)
                }
            }
        }
        let _ = out.flush();
        // Seen-map is for unique/summary; in annotate mode keep it bounded.
        if b.mode == BulkMode::Annotate && seen.len() > 200_000 {
            seen.clear();
        }
    }

    match b.mode {
        BulkMode::Annotate => {}
        BulkMode::Unique => {
            let mut rows: Vec<_> = seen.values().collect();
            rows.sort_by(|a, c| c.1.cmp(&a.1).then(a.0.ip.cmp(&c.0.ip)));
            match format {
                BulkFormat::Csv => {
                    let _ = writeln!(out, "ip,hits,asn,as_name,country,prefix,registry,org,network,cidr,abuse_email,private,error");
                    for (o, h) in rows {
                        let c = |s: &Option<String>| bulk::csv_escape(s.as_deref().unwrap_or(""));
                        let _ = writeln!(
                            out,
                            "{},{h},{},{},{},{},{},{},{},{},{},{},{}",
                            o.ip,
                            o.asn.map(|a| a.to_string()).unwrap_or_default(),
                            c(&o.as_name), c(&o.country), c(&o.prefix), c(&o.registry), c(&o.org),
                            c(&o.network), c(&o.cidr), c(&o.abuse_email), o.private, c(&o.error)
                        );
                    }
                }
                BulkFormat::Pretty => {
                    let _ = writeln!(out, "{:>7}  {:<39}  {:>9}  {:<3}  {:<20}  OWNER", "HITS", "IP", "ASN", "CC", "PREFIX");
                    for (o, h) in rows {
                        let owner = if o.private { "private / reserved".to_string() } else {
                            o.org.clone().or(o.as_name.clone()).or(o.error.clone()).unwrap_or_default()
                        };
                        let _ = writeln!(out, "{h:>7}  {:<39}  {:>9}  {:<3}  {:<20}  {owner}",
                            o.ip, o.asn.map(|a| format!("AS{a}")).unwrap_or_default(),
                            o.country.clone().unwrap_or_default(), o.prefix.clone().or(o.cidr.clone()).unwrap_or_default());
                    }
                }
                _ => {
                    for (o, h) in rows {
                        let mut v = serde_json::to_value(o).unwrap();
                        v["hits"] = serde_json::json!(h);
                        let _ = writeln!(out, "{v}");
                    }
                }
            }
        }
        BulkMode::Summary => {
            let groups = bulk::summarize(&seen, b.top);
            match format {
                BulkFormat::Csv => {
                    let _ = writeln!(out, "asn,owner,country,hits,unique_ips");
                    for g in groups {
                        let _ = writeln!(out, "{},{},{},{},{}", g.asn.map(|a| a.to_string()).unwrap_or_default(),
                            bulk::csv_escape(&g.owner), g.country.unwrap_or_default(), g.hits, g.unique_ips);
                    }
                }
                BulkFormat::Pretty => {
                    let total: usize = seen.values().map(|(_, h)| h).sum::<usize>().max(1);
                    let _ = writeln!(out, "{:>8}  {:>6}  {:>6}  {:>9}  {:<3}  OWNER", "HITS", "SHARE", "IPS", "ASN", "CC");
                    for g in groups {
                        let _ = writeln!(out, "{:>8}  {:>5.1}%  {:>6}  {:>9}  {:<3}  {}", g.hits, g.hits as f64 * 100.0 / total as f64,
                            g.unique_ips, g.asn.map(|a| format!("AS{a}")).unwrap_or_default(), g.country.unwrap_or_default(), g.owner);
                    }
                }
                _ => {
                    for g in groups {
                        let _ = writeln!(out, "{}", serde_json::to_string(&g).unwrap());
                    }
                }
            }
        }
    }
    let _ = out.flush();

    if !b.quiet {
        use std::sync::atomic::Ordering::Relaxed;
        let s = &engine.stats;
        let (dim, reset) = if std::io::stderr().is_terminal() { ("\x1b[2m", "\x1b[0m") } else { ("", "") };
        eprintln!(
            "{dim}whoq bulk: {} lines · {} unique IPs · {} cymru queries · {} rdap lookups · {} cache hits · {} errors · {:.1}s{reset}",
            total_lines, seen.len(), s.cymru_queries.load(Relaxed), s.rdap_lookups.load(Relaxed),
            s.cache_hits.load(Relaxed), s.errors.load(Relaxed), started.elapsed().as_secs_f64()
        );
    }
    if failed { exit::FAILED } else { exit::OK }
}

async fn run(a: LookupArgs) -> i32 {
    let stdout_tty = std::io::stdout().is_terminal();
    let format = match (a.json, a.output) {
        (true, _) => Format::Json,
        (_, Format::Auto) if stdout_tty => Format::Pretty,
        (_, Format::Auto) => Format::Ndjson,
        (_, f) => f,
    };
    let machine = format != Format::Pretty;

    let queries = read_queries(&a.queries);
    if queries.is_empty() {
        fatal(machine, "usage", "no queries given (try `whoq example.com` or `whoq --help`)");
    }

    let ctx = match Ctx::new(options(&a.common, a.raw, a.whois)) {
        Ok(c) => c,
        Err(e) => fatal(machine, "init", &e.to_string()),
    };
    let style = output::Style {
        color: stdout_tty && !a.no_color && std::env::var_os("NO_COLOR").is_none(),
    };

    let mut stream = futures::stream::iter(queries.clone())
        .map(|q| {
            let ctx = ctx.clone();
            async move { lookup::lookup(&ctx, &q).await }
        })
        .buffered(a.concurrency.clamp(1, 64));

    let mut stdout = std::io::stdout().lock();
    let mut json_all = Vec::new();
    let (mut failed, mut missing) = (false, false);
    let mut first = true;
    while let Some(rec) = stream.next().await {
        match rec.result {
            Outcome::Error => failed = true,
            Outcome::Available | Outcome::NotFound => missing = true,
            _ => {}
        }
        let projected = if !a.fields.is_empty() {
            Some(output::project(&rec, &a.fields))
        } else if a.brief {
            Some(output::project(&rec, &output::brief_fields(&rec)))
        } else {
            None
        };
        let value = || projected.clone().unwrap_or_else(|| serde_json::to_value(&rec).unwrap());
        let _ = match format {
            Format::Ndjson => writeln!(stdout, "{}", value()),
            Format::Json => {
                json_all.push(value());
                Ok(())
            }
            _ => {
                if !first {
                    let _ = writeln!(stdout);
                }
                let text = match &projected {
                    Some(p) => output::pretty_projection(p, &style),
                    None => output::pretty(&rec, &style),
                };
                write!(stdout, "{text}")
            }
        };
        let _ = stdout.flush();
        first = false;
    }
    if format == Format::Json {
        let v = if json_all.len() == 1 { json_all.pop().unwrap() } else { serde_json::Value::Array(json_all) };
        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&v).unwrap());
    }

    if failed {
        exit::FAILED
    } else if missing {
        exit::NOT_FOUND
    } else {
        exit::OK
    }
}
