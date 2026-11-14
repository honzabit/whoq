//! IANA RDAP bootstrap (RFC 9224): which RDAP server is authoritative for a
//! TLD, IP block or ASN range. Cached on disk for 24h; stale copies are used
//! if IANA is unreachable.

use crate::ctx::{Ctx, LookupError};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

const IANA: &str = "https://data.iana.org/rdap/";
const TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Deserialize)]
struct File {
    services: Vec<Vec<Vec<String>>>,
}

pub struct Registry {
    /// (entries, base urls)
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Clone, Copy)]
pub enum Space {
    Dns,
    Ipv4,
    Ipv6,
    Asn,
}

impl Space {
    fn file(self) -> &'static str {
        match self {
            Space::Dns => "dns",
            Space::Ipv4 => "ipv4",
            Space::Ipv6 => "ipv6",
            Space::Asn => "asn",
        }
    }
}

async fn load(ctx: &Ctx, space: Space) -> Result<Arc<Registry>, LookupError> {
    let name = space.file();
    let mut guard = ctx.bootstrap.lock().await;
    if let Some(r) = guard.get(name) {
        return Ok(r.clone());
    }

    let mut bytes = ctx.cache_get("bootstrap", name, TTL, false).await;
    if bytes.is_none() {
        let url = format!("{IANA}{name}.json");
        match fetch(ctx, &url).await {
            Ok(b) => {
                ctx.cache_put("bootstrap", name, &b).await;
                bytes = Some(b);
            }
            Err(e) => {
                bytes = ctx.cache_get("bootstrap", name, TTL, true).await;
                if bytes.is_none() {
                    return Err(e);
                }
            }
        }
    }
    let file: File = serde_json::from_slice(&bytes.unwrap())
        .map_err(|e| LookupError::Upstream(format!("bad IANA bootstrap {name}.json: {e}")))?;
    let services = file
        .services
        .into_iter()
        .filter_map(|mut s| {
            if s.len() < 2 {
                return None;
            }
            let urls = s.pop()?;
            let entries = s.pop()?;
            Some((entries.into_iter().map(|e| e.to_ascii_lowercase()).collect(), urls))
        })
        .collect();
    let reg = Arc::new(Registry { services });
    guard.insert(name, reg.clone());
    Ok(reg)
}

async fn fetch(ctx: &Ctx, url: &str) -> Result<Vec<u8>, LookupError> {
    let resp = ctx.http.get(url).send().await.map_err(|e| LookupError::Network(format!("{url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(LookupError::Upstream(format!("{url}: HTTP {}", resp.status())));
    }
    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| LookupError::Network(e.to_string()))
}

fn pick(urls: &[String]) -> Option<String> {
    let u = urls.iter().find(|u| u.starts_with("https://")).or_else(|| urls.first())?;
    Some(if u.ends_with('/') { u.clone() } else { format!("{u}/") })
}

/// Base URL of the RDAP server for a domain's TLD.
pub async fn for_domain(ctx: &Ctx, ascii: &str) -> Result<Option<String>, LookupError> {
    let reg = load(ctx, Space::Dns).await?;
    // Longest matching label suffix (entries are TLDs today, but the RFC allows more).
    let mut best: Option<(usize, &Vec<String>)> = None;
    for (entries, urls) in &reg.services {
        for e in entries {
            if (ascii == e || ascii.ends_with(&format!(".{e}"))) && best.is_none_or(|(l, _)| e.len() > l) {
                best = Some((e.len(), urls));
            }
        }
    }
    Ok(best.and_then(|(_, u)| pick(u)))
}

pub async fn for_net(ctx: &Ctx, net: IpNet) -> Result<Option<String>, LookupError> {
    let space = match net.addr() {
        IpAddr::V4(_) => Space::Ipv4,
        IpAddr::V6(_) => Space::Ipv6,
    };
    let reg = load(ctx, space).await?;
    let mut best: Option<(u8, &Vec<String>)> = None;
    for (entries, urls) in &reg.services {
        for e in entries {
            if let Ok(block) = e.parse::<IpNet>()
                && block.contains(&net)
                && best.is_none_or(|(l, _)| block.prefix_len() > l)
            {
                best = Some((block.prefix_len(), urls));
            }
        }
    }
    Ok(best.and_then(|(_, u)| pick(u)))
}

pub async fn for_asn(ctx: &Ctx, asn: u32) -> Result<Option<String>, LookupError> {
    let reg = load(ctx, Space::Asn).await?;
    for (entries, urls) in &reg.services {
        for e in entries {
            let (lo, hi) = match e.split_once('-') {
                Some((a, b)) => (a.parse::<u32>(), b.parse::<u32>()),
                None => (e.parse::<u32>(), e.parse::<u32>()),
            };
            if let (Ok(lo), Ok(hi)) = (lo, hi)
                && (lo..=hi).contains(&asn)
            {
                return Ok(pick(urls));
            }
        }
    }
    Ok(None)
}
