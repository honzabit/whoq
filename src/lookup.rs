//! Orchestration: query -> cache -> RDAP (registry, then registrar) -> port-43 fallback -> Record.

use crate::bootstrap;
use crate::ctx::{Ctx, LookupError};
use crate::model::{Kind, Outcome, Record, Source};
use crate::normalize::signals;
use crate::query::{self, Query};
use crate::rdap::{self, Got};
use crate::{sanitize, whois43};
use ipnet::IpNet;
use serde_json::Value;

fn kind_of(q: &Query) -> Kind {
    match q {
        Query::Domain { .. } => Kind::Domain,
        Query::Ip(_) | Query::Cidr(_) => Kind::Ip,
        Query::Asn(_) => Kind::Asn,
    }
}

fn cache_key(q: &Query, ctx: &Ctx) -> String {
    let base = match q {
        Query::Domain { ascii, .. } => ascii.clone(),
        Query::Ip(ip) => ip.to_string(),
        Query::Cidr(n) => n.to_string(),
        Query::Asn(n) => format!("as{n}"),
    };
    let mut k = base;
    if ctx.opts.raw {
        k.push_str(".raw");
    }
    if ctx.opts.force_whois {
        k.push_str(".whois");
    }
    k
}

pub async fn lookup(ctx: &Ctx, input: &str) -> Record {
    lookup_with(ctx, input, ctx.opts.cache_ttl).await
}

/// Like [`lookup`], but serve from cache only if the cached record is younger than `max_age`
/// (zero = always fetch fresh). A fresh result still refreshes the cache.
pub async fn lookup_with(ctx: &Ctx, input: &str, max_age: std::time::Duration) -> Record {
    let q = match query::parse(input) {
        Ok(q) => q,
        Err(e) => return Record::new(input, Kind::Domain).fail("invalid_query", e),
    };
    let key = cache_key(&q, ctx);

    if ctx.opts.use_cache
        && !max_age.is_zero()
        && let Some(bytes) = ctx.cache_get("results", &key, max_age, false).await
        && let Ok(mut rec) = serde_json::from_slice::<Record>(&bytes)
    {
        rec.query = input.to_string();
        if let Some(s) = &mut rec.source {
            s.cached = true;
        }
        // recompute time-relative signals; they drift while cached
        let privacy = rec.signals.as_ref().and_then(|s| s.privacy_redacted);
        rec.signals = signals(&rec, privacy);
        return rec;
    }

    let mut rec = Record::new(input, kind_of(&q));
    let mut redacted = false;
    let res = match &q {
        Query::Domain { ascii, unicode } => {
            rec.name = Some(ascii.clone());
            rec.unicode_name = unicode.clone();
            domain(ctx, &mut rec, ascii, &mut redacted).await
        }
        Query::Ip(ip) => {
            rec.name = Some(ip.to_string());
            ip_net(ctx, &mut rec, IpNet::from(*ip), &ip.to_string(), &mut redacted).await
        }
        Query::Cidr(net) => {
            rec.name = Some(net.to_string());
            ip_net(ctx, &mut rec, *net, &net.to_string(), &mut redacted).await
        }
        Query::Asn(n) => {
            rec.name = Some(format!("AS{n}"));
            asn(ctx, &mut rec, *n, &mut redacted).await
        }
    };

    match res {
        Ok(src) => {
            rec.source = Some(src);
            let has_registrant = rec.registrant.as_ref().is_some_and(|c| c.name.is_some() || c.org.is_some());
            let privacy =
                (rec.kind == Kind::Domain && rec.result == Outcome::Registered).then_some(redacted || !has_registrant);
            rec.signals = signals(&rec, privacy);
        }
        Err(e) => {
            rec = rec.fail(e.code(), e.message());
        }
    }
    sanitize::record(&mut rec);

    if ctx.opts.use_cache
        && rec.result != Outcome::Error
        && let Ok(bytes) = serde_json::to_vec(&rec)
    {
        ctx.cache_put("results", &key, &bytes).await;
    }
    rec
}

fn source(protocol: &str, servers: Vec<String>) -> Source {
    Source {
        protocol: protocol.into(),
        servers,
        cached: false,
        fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

async fn domain(ctx: &Ctx, rec: &mut Record, ascii: &str, redacted: &mut bool) -> Result<Source, LookupError> {
    let base = if ctx.opts.force_whois { None } else { bootstrap::for_domain(ctx, ascii).await? };
    let Some(base) = base else {
        let servers = whois43::lookup_domain(ctx, rec, ascii, redacted).await?;
        return Ok(source("whois", servers));
    };

    let url = format!("{base}domain/{ascii}");
    match rdap::get(ctx, &url).await {
        Ok(Got::NotFound) => {
            rec.result = Outcome::Available;
            Ok(source("rdap", vec![url]))
        }
        Ok(Got::Found(v)) => {
            rec.result = Outcome::Registered;
            rdap::apply_domain(rec, &v, redacted);
            let mut servers = vec![url.clone()];
            let mut raws = vec![v.clone()];
            if let Some(reg_url) = rdap::registrar_link(&v, &url) {
                // Registrar data is best-effort; registry data already answers the question.
                if let Ok(Got::Found(v2)) = rdap::get(ctx, &reg_url).await {
                    rdap::apply_domain(rec, &v2, redacted);
                    servers.push(reg_url);
                    raws.push(v2);
                }
            }
            if ctx.opts.raw {
                rec.raw = Some(Value::Array(raws));
            }
            Ok(source("rdap", servers))
        }
        // RDAP down? Fall back to port 43 before giving up.
        Err(e) => match whois43::lookup_domain(ctx, rec, ascii, redacted).await {
            Ok(servers) => Ok(source("whois", servers)),
            Err(_) => Err(e),
        },
    }
}

async fn ip_net(
    ctx: &Ctx,
    rec: &mut Record,
    net: IpNet,
    label: &str,
    redacted: &mut bool,
) -> Result<Source, LookupError> {
    // Every RIR runs RDAP and redirects cross-RIR; ARIN is a sane default if bootstrap misses.
    let base = bootstrap::for_net(ctx, net).await?.unwrap_or_else(|| "https://rdap.arin.net/registry/".into());
    let url = format!("{base}ip/{label}");
    match rdap::get(ctx, &url).await? {
        Got::NotFound => rec.result = Outcome::NotFound,
        Got::Found(v) => {
            rec.result = Outcome::Found;
            rdap::apply_ip(rec, &v, redacted);
            if ctx.opts.raw {
                rec.raw = Some(v);
            }
        }
    }
    Ok(source("rdap", vec![url]))
}

async fn asn(ctx: &Ctx, rec: &mut Record, n: u32, redacted: &mut bool) -> Result<Source, LookupError> {
    let base = bootstrap::for_asn(ctx, n)
        .await?
        .ok_or_else(|| LookupError::NoServer(format!("AS{n} is not allocated to any RIR")))?;
    let url = format!("{base}autnum/{n}");
    match rdap::get(ctx, &url).await? {
        Got::NotFound => rec.result = Outcome::NotFound,
        Got::Found(v) => {
            rec.result = Outcome::Found;
            rdap::apply_asn(rec, &v, redacted);
            if ctx.opts.raw {
                rec.raw = Some(v);
            }
        }
    }
    Ok(source("rdap", vec![url]))
}
