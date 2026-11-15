//! `whoq bulk`: enrich IPs found in logs with ASN / owner data, at log scale.
//!
//! Two sources:
//! - Team Cymru IP-to-ASN bulk whois (default): thousands of IPs per TCP connection;
//!   gives ASN, AS name, BGP prefix, country, RIR.
//! - RDAP (`--rdap`): network name, org, abuse contact. One request per *network*, not per IP —
//!   every answer is cached by its CIDR and reused for all other IPs inside it.
//!
//! Both caches persist on disk (default 7 days) so repeated runs are mostly offline.

use crate::ctx::Ctx;
use crate::lookup::lookup;
use crate::model::Outcome;
use crate::sanitize::clean;
use futures::StreamExt;
use ipnet::{IpNet, Ipv4Subnets, Ipv6Subnets};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CYMRU: &str = "whois.cymru.com";
const CYMRU_BATCH: usize = 1000;

// ---------------- IP extraction ----------------

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn token_ip(tok: &str) -> Option<IpAddr> {
    let t = tok.trim_matches(|c| c == '[' || c == ']' || c == '.');
    if t.is_empty() {
        return None;
    }
    let ip = t.parse::<IpAddr>().ok().or_else(|| {
        // 1.2.3.4:443  /  [2001:db8::1]:443 (brackets already split off)
        let (h, p) = t.rsplit_once(':')?;
        (h.contains('.') && p.chars().all(|c| c.is_ascii_digit())).then(|| h.parse().ok())?
    })?;
    (!ip.is_unspecified()).then(|| normalize(ip))
}

/// All distinct IPs in a piece of text, in order of appearance.
pub fn extract(text: &str) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '[' || c == ']'))
        .flat_map(|t| t.split(['[', ']']))
        .filter(|t| t.len() >= 2)
        .filter_map(token_ip)
        .filter(|ip| seen.insert(*ip))
        .collect()
}

pub fn extract_field(line: &str, field: usize, delim: Option<char>) -> Vec<IpAddr> {
    let col = match delim {
        Some(d) => line.split(d).nth(field - 1),
        None => line.split_whitespace().nth(field - 1),
    };
    col.map(|c| extract(c.trim_matches('"'))).unwrap_or_default()
}

/// Numeric weight from a 1-based field. Accepts `1,234`, `1_234` and `12.0`.
pub fn parse_weight(line: &str, field: usize, delim: Option<char>) -> Option<usize> {
    let col = match delim {
        Some(d) => line.split(d).nth(field - 1),
        None => line.split_whitespace().nth(field - 1),
    }?;
    let s: String = col.trim().trim_matches('"').chars().filter(|c| *c != ',' && *c != '_').collect();
    s.parse::<usize>()
        .ok()
        .or_else(|| s.parse::<f64>().ok().filter(|f| *f >= 0.0 && f.is_finite()).map(|f| f.round() as usize))
}

/// Non-routable addresses never leave the machine.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_broadcast()
                || v.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[0] == 0x0064 && s[1] == 0xff9b // NAT64 well-known
        }
    }
}

// ---------------- network-keyed cache ----------------

/// Longest-prefix-match map: one hash map per prefix length.
pub struct NetCache<T> {
    v4: BTreeMap<u8, HashMap<IpNet, T>>,
    v6: BTreeMap<u8, HashMap<IpNet, T>>,
}

impl<T: Clone> NetCache<T> {
    pub fn new() -> Self {
        NetCache { v4: BTreeMap::new(), v6: BTreeMap::new() }
    }
    pub fn insert(&mut self, net: IpNet, v: T) {
        let net = net.trunc();
        let m = if net.addr().is_ipv4() { &mut self.v4 } else { &mut self.v6 };
        m.entry(net.prefix_len()).or_default().insert(net, v);
    }
    pub fn get(&self, ip: IpAddr) -> Option<T> {
        let m = if ip.is_ipv4() { &self.v4 } else { &self.v6 };
        for (len, nets) in m.iter().rev() {
            if let Ok(n) = IpNet::new(ip, *len)
                && let Some(v) = nets.get(&n.trunc())
            {
                return Some(v.clone());
            }
        }
        None
    }
}

// ---------------- data ----------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CymruInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RdapInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_email: Option<String>,
}

/// Enrichment for one IP.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Owner {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// BGP prefix (Cymru)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Registered network (RDAP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_email: Option<String>,
    /// Reverse DNS name (`--rdns`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// The PTR name resolves back to this IP (`--rdns`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr_verified: Option<bool>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub private: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    k: String,
    net: String,
    t: u64,
    #[serde(default)]
    c: Option<CymruInfo>,
    #[serde(default)]
    r: Option<RdapInfo>,
}

#[derive(Default)]
pub struct Stats {
    pub cymru_queries: AtomicUsize,
    pub rdap_lookups: AtomicUsize,
    pub cache_hits: AtomicUsize,
    pub errors: AtomicUsize,
}

pub struct EngineOpts {
    pub cymru: bool,
    pub rdap: bool,
    /// Don't reuse RDAP networks larger than /24 (v4) or /48 (v6): more lookups, finer attribution.
    pub precise: bool,
    pub persist: bool,
    pub cache_ttl: Duration,
    pub concurrency: usize,
}

pub struct Engine {
    ctx: Arc<Ctx>,
    opts: EngineOpts,
    cymru: Mutex<NetCache<CymruInfo>>,
    rdap: Mutex<NetCache<RdapInfo>>,
    /// IPs Cymru had no answer for in this run (don't re-ask).
    cymru_failed: Mutex<HashMap<IpAddr, String>>,
    rdap_failed: Mutex<HashMap<IpAddr, String>>,
    persist_buf: Mutex<Vec<Persisted>>,
    pub stats: Stats,
}

/// Parse the cache file, dropping expired, malformed and superseded entries
/// (latest write per source+network wins). Returns (kept, total lines).
fn compact_entries(text: &str, cutoff: u64) -> (Vec<Persisted>, usize) {
    let mut latest: HashMap<(String, String), Persisted> = HashMap::new();
    let mut total = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        total += 1;
        let Ok(e) = serde_json::from_str::<Persisted>(line) else { continue };
        if e.t < cutoff || e.net.parse::<IpNet>().is_err() {
            continue;
        }
        let key = (e.k.clone(), e.net.clone());
        if latest.get(&key).is_none_or(|old| e.t >= old.t) {
            latest.insert(key, e);
        }
    }
    let mut kept: Vec<Persisted> = latest.into_values().collect();
    kept.sort_by(|a, b| a.t.cmp(&b.t).then(a.net.cmp(&b.net)));
    (kept, total)
}

/// Atomic rewrite (temp file + rename). A run appending concurrently may lose its
/// newest entries; that only costs a re-lookup later.
fn rewrite(path: &std::path::Path, kept: &[Persisted]) {
    let mut buf = String::new();
    for e in kept {
        if let Ok(s) = serde_json::to_string(e) {
            buf.push_str(&s);
            buf.push('\n');
        }
    }
    let tmp = path.with_extension(format!("compact{}", std::process::id()));
    if std::fs::write(&tmp, buf).is_ok() && std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn bucket(ip: IpAddr) -> IpNet {
    let len = if ip.is_ipv4() { 24 } else { 48 };
    IpNet::new(ip, len).unwrap().trunc()
}

fn range_to_nets(start: &str, end: &str) -> Vec<IpNet> {
    match (start.parse::<IpAddr>(), end.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => Ipv4Subnets::new(a, b, 0).map(IpNet::V4).take(64).collect(),
        (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => Ipv6Subnets::new(a, b, 0).map(IpNet::V6).take(64).collect(),
        _ => vec![],
    }
}

/// Parse a Team Cymru verbose bulk answer into (ip, info) pairs.
pub fn parse_cymru(text: &str) -> Vec<(IpAddr, CymruInfo)> {
    text.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('|').map(str::trim).collect();
            if parts.len() < 7 {
                return None;
            }
            let ip = normalize(parts[1].parse::<IpAddr>().ok()?);
            Some((
                ip,
                CymruInfo {
                    asn: parts[0].parse().ok(),
                    prefix: parts[2].parse::<IpNet>().ok().map(|n| n.to_string()),
                    country: opt_clean(parts[3]),
                    registry: opt_clean(parts[4]),
                    as_name: opt_clean(&parts[6..].join("|")),
                },
            ))
        })
        .collect()
}

/// Ask Team Cymru about a handful of IPs (no caching; for `--dns` hosting).
pub async fn cymru_lookup(ctx: &Ctx, ips: &[IpAddr]) -> Result<Vec<(IpAddr, CymruInfo)>, crate::ctx::LookupError> {
    let body = format!("begin\nverbose\n{}\nend", ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("\n"));
    Ok(parse_cymru(&crate::whois43::query(ctx, CYMRU, &body).await?))
}

fn opt_clean(s: &str) -> Option<String> {
    let c = clean(s, 200);
    (!c.is_empty() && c != "NA").then_some(c)
}

impl Engine {
    pub fn new(ctx: Arc<Ctx>, opts: EngineOpts) -> Arc<Engine> {
        let e = Engine {
            ctx,
            opts,
            cymru: Mutex::new(NetCache::new()),
            rdap: Mutex::new(NetCache::new()),
            cymru_failed: Mutex::new(HashMap::new()),
            rdap_failed: Mutex::new(HashMap::new()),
            persist_buf: Mutex::new(vec![]),
            stats: Stats::default(),
        };
        if e.opts.persist {
            e.load();
        }
        Arc::new(e)
    }

    fn cache_file(&self) -> Option<std::path::PathBuf> {
        Some(self.ctx.cache_dir.as_ref()?.join("bulk").join("networks.ndjson"))
    }

    fn load(&self) {
        let Some(p) = self.cache_file() else { return };
        let Ok(text) = std::fs::read_to_string(&p) else { return };
        let cutoff = now_secs().saturating_sub(self.opts.cache_ttl.as_secs());
        let (kept, total) = compact_entries(&text, cutoff);
        {
            let (mut c, mut r) = (self.cymru.lock().unwrap(), self.rdap.lock().unwrap());
            for e in &kept {
                let Ok(net) = e.net.parse::<IpNet>() else { continue };
                match (e.k.as_str(), &e.c, &e.r) {
                    ("cymru", Some(v), _) => c.insert(net, v.clone()),
                    ("rdap", _, Some(v)) => r.insert(net, v.clone()),
                    _ => {}
                }
            }
        }
        // Append-only grows forever; rewrite once a meaningful share is expired or duplicate.
        let dead = total - kept.len();
        if dead >= 500 || (total > 0 && dead * 4 >= total && dead > 20) {
            rewrite(&p, &kept);
        }
    }

    /// Append newly learned networks to the on-disk cache.
    pub fn flush(&self) {
        if !self.opts.persist {
            return;
        }
        let items: Vec<Persisted> = std::mem::take(&mut *self.persist_buf.lock().unwrap());
        if items.is_empty() {
            return;
        }
        let Some(p) = self.cache_file() else { return };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            let mut buf = String::new();
            for it in items {
                if let Ok(s) = serde_json::to_string(&it) {
                    buf.push_str(&s);
                    buf.push('\n');
                }
            }
            let _ = f.write_all(buf.as_bytes());
        }
    }

    async fn cymru_batch(&self, ips: Vec<IpAddr>) {
        self.stats.cymru_queries.fetch_add(1, Ordering::Relaxed);
        let body = format!("begin\nverbose\n{}\nend", ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("\n"));
        let resp = crate::whois43::query(&self.ctx, CYMRU, &body).await;
        let text = match resp {
            Ok(t) => t,
            Err(e) => {
                let mut f = self.cymru_failed.lock().unwrap();
                for ip in ips {
                    f.insert(ip, format!("cymru: {}", e.message()));
                }
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let mut answered = HashSet::new();
        let t = now_secs();
        let mut cache = self.cymru.lock().unwrap();
        let mut pbuf = self.persist_buf.lock().unwrap();
        for (ip, info) in parse_cymru(&text) {
            let net = info.prefix.as_deref().and_then(|p| p.parse::<IpNet>().ok()).unwrap_or_else(|| IpNet::from(ip));
            cache.insert(net, info.clone());
            pbuf.push(Persisted { k: "cymru".into(), net: net.to_string(), t, c: Some(info), r: None });
            answered.insert(ip);
        }
        let mut f = self.cymru_failed.lock().unwrap();
        for ip in ips.into_iter().filter(|i| !answered.contains(i)) {
            f.insert(ip, "cymru: no answer".into());
        }
    }

    async fn rdap_one(&self, ip: IpAddr) {
        if self.rdap.lock().unwrap().get(ip).is_some() {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.stats.rdap_lookups.fetch_add(1, Ordering::Relaxed);
        let rec = lookup(&self.ctx, &ip.to_string()).await;
        if rec.result != Outcome::Found {
            let msg = rec.error.map(|e| format!("rdap: {}", e.code)).unwrap_or_else(|| "rdap: not found".into());
            self.rdap_failed.lock().unwrap().insert(ip, msg);
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let n = rec.network.unwrap_or_default();
        let mut nets: Vec<IpNet> = n.cidr.iter().filter_map(|c| c.parse().ok()).collect();
        if nets.is_empty()
            && let (Some(a), Some(b)) = (&n.start, &n.end)
        {
            nets = range_to_nets(a, b);
        }
        if nets.is_empty() || !nets.iter().any(|x| x.contains(&ip)) {
            nets = vec![IpNet::from(ip)];
        }
        let info = RdapInfo {
            org: n.org,
            network: n.name,
            cidr: nets.iter().find(|x| x.contains(&ip)).map(|x| x.to_string()),
            net_type: n.net_type,
            country: n.country,
            abuse_email: rec.abuse_email,
        };
        let b = bucket(ip);
        let t = now_secs();
        let mut cache = self.rdap.lock().unwrap();
        let mut pbuf = self.persist_buf.lock().unwrap();
        for net in nets {
            let scope =
                if self.opts.precise && net.prefix_len() < b.prefix_len() && net.contains(&ip) { b } else { net };
            cache.insert(scope, info.clone());
            pbuf.push(Persisted { k: "rdap".into(), net: scope.to_string(), t, c: None, r: Some(info.clone()) });
        }
    }

    /// Resolve a set of IPs; lookups only happen for IPs not covered by a cached network.
    pub async fn resolve(&self, ips: &HashSet<IpAddr>) -> HashMap<IpAddr, Owner> {
        let public: Vec<IpAddr> = ips.iter().copied().filter(|i| !is_private(i)).collect();

        if self.opts.cymru {
            let missing: Vec<IpAddr> = {
                let c = self.cymru.lock().unwrap();
                let f = self.cymru_failed.lock().unwrap();
                public.iter().copied().filter(|i| c.get(*i).is_none() && !f.contains_key(i)).collect()
            };
            self.stats.cache_hits.fetch_add(public.len() - missing.len(), Ordering::Relaxed);
            futures::stream::iter(missing.chunks(CYMRU_BATCH).map(|c| c.to_vec()))
                .for_each_concurrent(2, |batch| self.cymru_batch(batch))
                .await;
        }

        if self.opts.rdap {
            // Group by /24 (/48): IPs in a bucket go sequentially so the first answer
            // usually covers the rest; buckets run in parallel.
            let mut buckets: HashMap<IpNet, Vec<IpAddr>> = HashMap::new();
            {
                let c = self.rdap.lock().unwrap();
                let f = self.rdap_failed.lock().unwrap();
                for ip in &public {
                    if c.get(*ip).is_none() && !f.contains_key(ip) {
                        buckets.entry(bucket(*ip)).or_default().push(*ip);
                    }
                }
            }
            futures::stream::iter(buckets.into_values())
                .for_each_concurrent(self.opts.concurrency.max(1), |ips| async move {
                    for ip in ips {
                        self.rdap_one(ip).await;
                    }
                })
                .await;
        }

        let (c, r) = (self.cymru.lock().unwrap(), self.rdap.lock().unwrap());
        let (cf, rf) = (self.cymru_failed.lock().unwrap(), self.rdap_failed.lock().unwrap());
        ips.iter()
            .map(|ip| {
                let mut o = Owner { ip: ip.to_string(), ..Default::default() };
                if is_private(ip) {
                    o.private = true;
                    return (*ip, o);
                }
                let mut errs = vec![];
                if self.opts.cymru {
                    if let Some(ci) = c.get(*ip) {
                        o.asn = ci.asn;
                        o.as_name = ci.as_name;
                        o.country = ci.country;
                        o.prefix = ci.prefix;
                        o.registry = ci.registry;
                    } else if let Some(e) = cf.get(ip) {
                        errs.push(e.clone());
                    }
                }
                if self.opts.rdap {
                    if let Some(ri) = r.get(*ip) {
                        o.org = ri.org;
                        o.network = ri.network;
                        o.cidr = ri.cidr;
                        o.abuse_email = ri.abuse_email;
                        if o.country.is_none() {
                            o.country = ri.country;
                        }
                    } else if let Some(e) = rf.get(ip) {
                        errs.push(e.clone());
                    }
                }
                if !errs.is_empty() {
                    o.error = Some(errs.join("; "));
                }
                (*ip, o)
            })
            .collect()
    }
}

/// Attach reverse DNS to owners, resolving IPs not yet in `cache` (kept across calls).
pub async fn attach_rdns(
    ctx: &Ctx,
    owners: &mut HashMap<IpAddr, Owner>,
    cache: &mut HashMap<IpAddr, crate::model::Rdns>,
    concurrency: usize,
) {
    let todo: Vec<IpAddr> = owners.keys().filter(|ip| !is_private(ip) && !cache.contains_key(ip)).copied().collect();
    let found: Vec<(IpAddr, crate::model::Rdns)> = futures::stream::iter(todo)
        .map(|ip| async move { (ip, crate::dns::rdns(ctx, ip).await) })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    cache.extend(found);
    for (ip, o) in owners.iter_mut() {
        if let Some(r) = cache.get(ip) {
            o.ptr = r.ptr.first().cloned();
            o.ptr_verified = r.verified;
        }
    }
}

// ---------------- aggregation ----------------

#[derive(Serialize, Clone)]
pub struct Group {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub hits: usize,
    pub unique_ips: usize,
}

pub fn summarize(seen: &HashMap<IpAddr, (Owner, usize)>, top: usize) -> Vec<Group> {
    let mut g: HashMap<String, Group> = HashMap::new();
    for (o, hits) in seen.values() {
        let (key, owner) = if o.private {
            ("private".to_string(), "private / reserved".to_string())
        } else if let Some(a) = o.asn {
            (format!("as{a}"), o.as_name.clone().or(o.org.clone()).unwrap_or_default())
        } else if let Some(org) = &o.org {
            (format!("org:{org}"), org.clone())
        } else {
            ("unknown".into(), "unknown".into())
        };
        let e = g.entry(key).or_insert_with(|| Group {
            asn: o.asn,
            owner,
            country: o.country.clone(),
            hits: 0,
            unique_ips: 0,
        });
        e.hits += hits;
        e.unique_ips += 1;
    }
    let mut v: Vec<Group> = g.into_values().collect();
    v.sort_by(|a, b| b.hits.cmp(&a.hits).then(b.unique_ips.cmp(&a.unique_ips)).then(a.owner.cmp(&b.owner)));
    if top > 0 {
        v.truncate(top);
    }
    v
}

pub fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ips_from_log_lines() {
        let l = r#"203.0.113.9 - - [14/Nov/2026:10:20:30 +0000] "GET / HTTP/1.1" 200 x-forwarded-for=8.8.8.8:443, [2001:4860:4860::8888]:53 v=::ffff:1.1.1.1 ts=12:34:56"#;
        let ips: Vec<String> = extract(l).iter().map(|i| i.to_string()).collect();
        assert_eq!(ips, vec!["203.0.113.9", "8.8.8.8", "2001:4860:4860::8888", "1.1.1.1"]);
        assert!(extract("deadbeef cafe:babe 2026-11-14 :: 10:20").is_empty());
        let f: Vec<String> = extract_field("a,b,9.9.9.9,c", 3, Some(',')).iter().map(|i| i.to_string()).collect();
        assert_eq!(f, vec!["9.9.9.9"]);
    }

    #[test]
    fn compaction_keeps_latest_unexpired() {
        let line = |k: &str, net: &str, t: u64, asn: u32| {
            serde_json::to_string(&Persisted {
                k: k.into(),
                net: net.into(),
                t,
                c: Some(CymruInfo { asn: Some(asn), ..Default::default() }),
                r: None,
            })
            .unwrap()
        };
        let text = [
            line("cymru", "8.8.8.0/24", 100, 1), // superseded
            line("cymru", "8.8.8.0/24", 200, 2), // kept
            line("cymru", "1.1.1.0/24", 50, 3),  // expired
            line("rdap", "8.8.8.0/24", 150, 4),  // different source: kept
            "not json".to_string(),              // malformed
            line("cymru", "garbage", 300, 5),    // bad net
        ]
        .join("\n");
        let (kept, total) = compact_entries(&text, 60);
        assert_eq!(total, 6);
        assert_eq!(kept.len(), 2);
        let c = kept.iter().find(|e| e.k == "cymru").unwrap();
        assert_eq!((c.t, c.c.as_ref().unwrap().asn), (200, Some(2)));
    }

    #[test]
    fn weights() {
        assert_eq!(parse_weight("8.8.8.8\t4171", 2, None), Some(4171));
        assert_eq!(parse_weight("8.8.8.8;1_234", 2, Some(';')), Some(1234));
        assert_eq!(parse_weight("8.8.8.8 12.0", 2, None), Some(12));
        assert_eq!(parse_weight("8.8.8.8 n/a", 2, None), None);
        assert_eq!(parse_weight("8.8.8.8", 2, None), None);
    }

    #[test]
    fn private_ranges() {
        for p in ["10.1.2.3", "192.168.0.1", "100.64.1.1", "127.0.0.1", "fe80::1", "fd00::1", "203.0.113.9"] {
            assert!(is_private(&p.parse().unwrap()), "{p}");
        }
        for p in ["8.8.8.8", "2606:4700::1111", "100.128.0.1"] {
            assert!(!is_private(&p.parse().unwrap()), "{p}");
        }
    }

    #[test]
    fn longest_prefix_match() {
        let mut c = NetCache::new();
        c.insert("8.0.0.0/8".parse().unwrap(), "big");
        c.insert("8.8.8.0/24".parse().unwrap(), "small");
        assert_eq!(c.get("8.8.8.8".parse().unwrap()), Some("small"));
        assert_eq!(c.get("8.1.1.1".parse().unwrap()), Some("big"));
        assert_eq!(c.get("9.9.9.9".parse().unwrap()), None);
    }
}
