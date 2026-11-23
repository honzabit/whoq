//! `whoq watch`: snapshot records, diff against the last run, raise alerts.
//! One-shot by default (cron/CI friendly); `--interval` keeps it running.

use crate::model::{Outcome, Record};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Fields that change on every fetch or are derived; never diffed.
const VOLATILE: &[&str] = &["schema", "query", "source", "signals", "raw", "error", "remarks"];

/// Live fields that churn on their own (CDN addresses, every certificate renewal); never diffed.
/// Renewals are tracked by the certificate alerts instead.
const VOLATILE_LIVE: &[&str] = &[
    "dns.host",
    "dns.a",
    "dns.aaaa",
    "tls.ip",
    "tls.sha256",
    "tls.not_before",
    "tls.not_after",
    "tls.expires_in_days",
    "tls.names_total",
];

/// Live sections, and whether `r` has a copy worth comparing. A transient failure (timeout,
/// resolver error) is not; NXDOMAIN is, because the name really has gone from DNS.
fn live_sections(r: &Record) -> [(&'static str, bool); 4] {
    let real = |e: &Option<String>| e.as_deref().is_none_or(|e| e.starts_with("NXDOMAIN"));
    [
        ("dns", r.dns.as_ref().is_some_and(|d| real(&d.error))),
        ("mail", r.mail.as_ref().is_some_and(|m| real(&m.error))),
        ("tls", r.tls.as_ref().is_some_and(|t| t.error.is_none())),
        ("rdns", r.rdns.as_ref().is_some_and(|x| x.error.is_none())),
    ]
}

/// Keep the last good copy of a live section that failed transiently this round, so the next
/// round still compares against real data.
fn carry_forward(old: &Record, new: &mut Record) {
    for ((name, old_ok), (_, new_ok)) in live_sections(old).into_iter().zip(live_sections(new)) {
        if old_ok && !new_ok {
            match name {
                "dns" if new.dns.is_some() => new.dns = old.dns.clone(),
                "mail" if new.mail.is_some() => new.mail = old.mail.clone(),
                "tls" if new.tls.is_some() => new.tls = old.tls.clone(),
                "rdns" if new.rdns.is_some() => new.rdns = old.rdns.clone(),
                _ => {}
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub record: Record,
    pub seen_at: String,
    /// Alert ids already delivered (e.g. `expiring:2026-12-01T00:00:00Z`), so alerts fire once.
    #[serde(default)]
    pub alerts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Change {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<Value>,
    /// For list fields: elements removed / added.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<Value>,
    pub severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn state_dir(over: Option<PathBuf>) -> Option<PathBuf> {
    over.or_else(|| std::env::var_os("WHOQ_STATE_DIR").map(PathBuf::from))
        .or_else(|| dirs::data_dir().map(|d| d.join("whoq").join("watch")))
}

/// What a snapshot is kept under and labelled as: for domains the host as given (so
/// `shop.example.com` and `www.example.com` are watched separately, which matters for `--tls`),
/// otherwise the normalized name.
pub fn label(rec: &Record) -> String {
    let host = match rec.kind {
        crate::model::Kind::Domain => crate::query::endpoint(&rec.query).map(|(h, _)| h),
        _ => None,
    };
    host.or_else(|| rec.name.clone()).unwrap_or_else(|| rec.query.clone()).to_lowercase()
}

fn key(label: &str) -> String {
    label.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect()
}

pub fn load(dir: &Path, label: &str) -> Option<Snapshot> {
    let bytes = std::fs::read(dir.join(format!("{}.json", key(label)))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save(dir: &Path, label: &str, snap: &Snapshot) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join(format!("{}.json", key(label)));
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(snap)?)?;
    std::fs::rename(tmp, p)
}

fn flatten(v: &Value, prefix: &str, out: &mut Map<String, Value>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(v, &p, out);
            }
        }
        Value::Array(a) => {
            // order-insensitive: registries shuffle nameservers/status freely
            let mut a = a.clone();
            a.sort_by_key(|x| x.to_string());
            out.insert(prefix.to_string(), Value::Array(a));
        }
        Value::Null => {}
        other => {
            out.insert(prefix.to_string(), other.clone());
        }
    }
}

fn stable(rec: &Record) -> Map<String, Value> {
    let mut v = serde_json::to_value(rec).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        for k in VOLATILE {
            m.remove(*k);
        }
    }
    // Hosting: which networks serve the site matters, not which of their addresses answered.
    if let Some(h) = v.pointer_mut("/dns/hosting") {
        let mut nets: Vec<Value> = h
            .as_array()
            .into_iter()
            .flatten()
            .map(|n| match (n["asn"].as_u64(), n["name"].as_str()) {
                (Some(a), Some(name)) => json!(format!("AS{a} {name}")),
                (Some(a), None) => json!(format!("AS{a}")),
                _ => json!(n["name"]),
            })
            .collect();
        nets.dedup();
        *h = Value::Array(nets);
    }
    let mut out = Map::new();
    flatten(&v, "", &mut out);
    for k in VOLATILE_LIVE {
        out.remove(*k);
    }
    out
}

fn severity(field: &str, removed: &[Value]) -> (&'static str, Option<String>) {
    let lock_removed = removed.iter().filter_map(|v| v.as_str()).find(|s| s.contains("transfer prohibited"));
    match field {
        "status" if lock_removed.is_some() => {
            ("high", Some(format!("transfer lock removed ({})", lock_removed.unwrap())))
        }
        "result" | "nameservers" | "registrar.name" | "registrar.iana_id" | "transferred" | "created"
        | "network.org" | "asn.org" | "network.cidr" => ("high", None),
        "status" | "expires" | "dnssec" | "abuse_email" | "network.name" | "asn.name" => ("medium", None),
        // live: delegation, mail routing and certificate trust are what hijacks change
        "dns.ns" | "dns.provider" | "dns.error" | "mail.mx" | "mail.provider" | "mail.error" | "tls.valid"
        | "tls.problem" => ("high", None),
        "dns.hosting"
        | "dns.caa"
        | "mail.null_mx"
        | "mail.dmarc.policy"
        | "mail.dmarc.subdomain_policy"
        | "mail.spf.all"
        | "mail.spf.record"
        | "tls.issuer"
        | "rdns.ptr"
        | "rdns.verified" => ("medium", None),
        f if f.starts_with("registrant.") || f.starts_with("registrar.") => ("medium", None),
        _ => ("low", None),
    }
}

pub fn diff(old: &Record, new: &Record, ignore: &[String]) -> Vec<Change> {
    let (mut a, mut b) = (stable(old), stable(new));
    // Snapshots from before whoq dropped placeholder expiries still hold one.
    for m in [&mut a, &mut b] {
        if m.get("expires").and_then(Value::as_str).is_some_and(crate::normalize::is_placeholder_expiry) {
            m.remove("expires");
        }
    }
    // Baselines saved before whoq read the registrant's state have none: not a change.
    if !a.contains_key("registrant.state") {
        b.remove("registrant.state");
    }
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    // A live section is compared only when both runs have a usable copy: turning --dns/--mail/
    // --tls on or off, or a transient failure, is not a change.
    let skip: Vec<&str> = live_sections(old)
        .into_iter()
        .zip(live_sections(new))
        .filter(|((_, o), (_, n))| !(*o && *n))
        .map(|((name, _), _)| name)
        .collect();
    let under = |k: &str, p: &str| k == p || k.starts_with(&format!("{p}."));
    let mut out = vec![];
    for k in keys {
        if ignore.iter().any(|i| under(k, i)) || skip.iter().any(|p| under(k, p)) {
            continue;
        }
        let (o, n) = (a.get(k), b.get(k));
        if o == n {
            continue;
        }
        let (mut removed, mut added) = (vec![], vec![]);
        if let (Some(Value::Array(oa)), Some(Value::Array(na))) = (o, n) {
            removed = oa.iter().filter(|x| !na.contains(x)).cloned().collect();
            added = na.iter().filter(|x| !oa.contains(x)).cloned().collect();
        } else if let (Some(Value::Array(oa)), None) = (o, n) {
            removed = oa.clone();
        } else if let (None, Some(Value::Array(na))) = (o, n) {
            added = na.clone();
        }
        let is_list = !removed.is_empty() || !added.is_empty();
        let (mut sev, mut note) = severity(k, &removed);
        if k == "result" {
            note = match (old.result, new.result) {
                (Outcome::Registered, Outcome::Available) => Some("domain dropped — now available".into()),
                (Outcome::Available, Outcome::Registered) => Some("domain was registered".into()),
                _ => None,
            };
        }
        if k == "expires" {
            // a later expiry is just a renewal — good news, not an alarm
            if let (Some(Value::String(os)), Some(Value::String(ns))) = (o, n)
                && ns > os
            {
                sev = "low";
                note = Some("renewed".into());
            }
        }
        out.push(Change {
            field: k.clone(),
            old: if is_list { None } else { o.cloned() },
            new: if is_list { None } else { n.cloned() },
            removed,
            added,
            severity: sev,
            note,
        });
    }
    out
}

fn worst(changes: &[Change]) -> &'static str {
    ["high", "medium", "low"].into_iter().find(|s| changes.iter().any(|c| c.severity == *s)).unwrap_or("low")
}

pub struct RoundOpts<'a> {
    pub dir: &'a Path,
    pub ignore: &'a [String],
    pub expiry_warn_days: i64,
    pub cert_warn_days: i64,
    pub show_unchanged: bool,
}

/// Process one fresh record: compare with its snapshot, update state, return events.
pub fn process(mut rec: Record, o: &RoundOpts) -> Vec<Value> {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let name = label(&rec);
    let query = rec.query.clone();
    let base = |event: &str| json!({ "event": event, "at": now, "query": query, "name": name });

    if rec.result == Outcome::Error {
        // Never overwrite a good snapshot with a failed lookup.
        let mut e = base("error");
        e["error"] = serde_json::to_value(&rec.error).unwrap_or(Value::Null);
        return vec![e];
    }

    let prev = load(o.dir, &name);
    if let Some(p) = &prev {
        carry_forward(&p.record, &mut rec);
    }
    let mut alerts_sent = prev.as_ref().map(|p| p.alerts.clone()).unwrap_or_default();
    // Ids of every alert condition true right now; delivered ids not in here are forgotten,
    // so a condition that clears and comes back alerts again.
    let mut active: Vec<String> = vec![];
    let mut fire = |id: String, e: Value, events: &mut Vec<Value>| {
        if !alerts_sent.contains(&id) {
            events.push(e);
            alerts_sent.push(id.clone());
        }
        active.push(id);
    };
    let mut events = vec![];

    match &prev {
        None => {
            let mut e = base("baseline");
            e["result"] = json!(rec.result);
            events.push(e);
        }
        Some(p) => {
            let changes = diff(&p.record, &rec, o.ignore);
            if changes.is_empty() {
                if o.show_unchanged {
                    events.push(base("unchanged"));
                }
            } else {
                let mut e = base("changed");
                e["severity"] = json!(worst(&changes));
                e["since"] = json!(p.seen_at);
                e["changes"] = serde_json::to_value(&changes).unwrap_or(Value::Null);
                events.push(e);
            }
        }
    }

    // Threshold alerts fire once per expiry date (a renewal changes the date and re-arms them).
    if let (Some(days), Some(exp)) = (rec.signals.as_ref().and_then(|s| s.expires_in_days), rec.expires.as_ref()) {
        let kind = if days < 0 {
            Some("expired")
        } else if days <= o.expiry_warn_days {
            Some("expiring")
        } else {
            None
        };
        if let Some(kind) = kind {
            let mut e = base("alert");
            e["alert"] = json!(kind);
            e["severity"] = json!("high");
            e["expires"] = json!(exp);
            e["expires_in_days"] = json!(days);
            fire(format!("{kind}:{exp}"), e, &mut events);
        }
    }
    if rec.signals.as_ref().and_then(|s| s.on_hold) == Some(true) {
        let mut e = base("alert");
        e["alert"] = json!("on_hold");
        e["severity"] = json!("high");
        e["status"] = json!(rec.status);
        fire(format!("on_hold:{}", rec.status.join(",")), e, &mut events);
    }
    // Certificate alerts fire once per certificate (a renewal brings a new one and re-arms them).
    if let Some(t) = rec.tls.as_ref().filter(|t| t.error.is_none()) {
        let cert = t.sha256.clone().unwrap_or_default();
        let tls_alert = |kind: &str| {
            let mut e = base("alert");
            e["alert"] = json!(kind);
            e["severity"] = json!("high");
            e["host"] = json!(t.host);
            e["not_after"] = json!(t.not_after);
            e["expires_in_days"] = json!(t.expires_in_days);
            e
        };
        match t.expires_in_days {
            Some(d) if d < 0 => fire(format!("cert_expired:{cert}"), tls_alert("cert_expired"), &mut events),
            Some(d) if d <= o.cert_warn_days => {
                fire(format!("cert_expiring:{cert}"), tls_alert("cert_expiring"), &mut events)
            }
            _ => {}
        }
        // Expiry has its own alert above; flag every other way a certificate can be untrusted.
        if t.valid == Some(false) && t.problem.as_deref() != Some("expired") {
            let mut e = tls_alert("cert_invalid");
            e["problem"] = json!(t.problem);
            fire(format!("cert_invalid:{cert}"), e, &mut events);
        }
    }
    // Certificate state from a run whose TLS check failed is unknown, not cleared.
    let tls_unknown = rec.tls.as_ref().is_some_and(|t| t.error.is_some());
    alerts_sent.retain(|a| active.contains(a) || (tls_unknown && a.starts_with("cert_")));

    let save_err = base("error");
    let snap = Snapshot { record: rec, seen_at: now, alerts: alerts_sent };
    if let Err(e) = save(o.dir, &name, &snap) {
        let mut ev = save_err;
        ev["error"] = json!({ "code": "state", "message": format!("could not save snapshot: {e}") });
        events.push(ev);
    }
    events
}

pub fn is_actionable(e: &Value) -> bool {
    matches!(e["event"].as_str(), Some("changed") | Some("alert"))
}

/// One-line summary for webhooks / chat.
pub fn summary(events: &[Value]) -> String {
    let parts: Vec<String> = events
        .iter()
        .filter(|e| is_actionable(e))
        .map(|e| {
            let name = e["name"].as_str().unwrap_or("?");
            match e["event"].as_str() {
                Some("alert") => format!("{name}: {} ({})", e["alert"].as_str().unwrap_or(""), e["expires_in_days"]),
                _ => {
                    let fields: Vec<&str> = e["changes"]
                        .as_array()
                        .map(|c| c.iter().filter_map(|x| x["field"].as_str()).collect())
                        .unwrap_or_default();
                    format!("{name}: {} changed [{}]", fields.join(", "), e["severity"].as_str().unwrap_or(""))
                }
            }
        })
        .collect();
    format!("whoq watch: {}", parts.join("; "))
}

/// Parse `90`, `90s`, `15m`, `6h`, `1d`.
pub fn parse_interval(s: &str) -> Result<std::time::Duration, String> {
    let d = crate::normalize::parse_duration(s)?;
    if d.as_secs() < 60 {
        return Err("interval must be at least 60s (be kind to registries)".into());
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Kind, Registrar};

    fn rec() -> Record {
        let mut r = Record::new("example.com", Kind::Domain);
        r.result = Outcome::Registered;
        r.name = Some("example.com".into());
        r.nameservers = vec!["a.ns.net".into(), "b.ns.net".into()];
        r.status = vec!["client transfer prohibited".into(), "client delete prohibited".into()];
        r.expires = Some("2027-01-01T00:00:00Z".into());
        r.registrar = Some(Registrar { name: Some("Good Registrar".into()), ..Default::default() });
        r
    }

    #[test]
    fn placeholder_expiry_in_an_old_snapshot_is_not_a_change() {
        let mut old = rec();
        old.expires = Some("3000-01-01T00:00:00Z".into());
        let mut new = rec();
        new.expires = None;
        assert!(diff(&old, &new, &[]).is_empty());
    }

    #[test]
    fn state_missing_from_an_old_baseline_is_not_a_change() {
        let with = |s: &str| {
            let mut r = rec();
            r.registrant = Some(crate::model::Contact { state: Some(s.into()), ..Default::default() });
            r
        };
        let mut old = rec();
        old.registrant = Some(crate::model::Contact { country: Some("GR".into()), ..Default::default() });
        let mut new = with("Attica");
        new.registrant.as_mut().unwrap().country = Some("GR".into());
        assert!(diff(&old, &new, &[]).is_empty());
        assert_eq!(diff(&with("Attica"), &with("Crete"), &[]).len(), 1);
    }

    #[test]
    fn no_noise_on_reorder() {
        let a = rec();
        let mut b = rec();
        b.nameservers.reverse();
        b.source = Some(crate::model::Source { protocol: "rdap".into(), fetched_at: "x".into(), ..Default::default() });
        assert!(diff(&a, &b, &[]).is_empty());
    }

    #[test]
    fn hijack_shape() {
        let a = rec();
        let mut b = rec();
        b.nameservers = vec!["ns1.evil.example".into()];
        b.status = vec!["client delete prohibited".into()];
        b.registrar.as_mut().unwrap().name = Some("Other Registrar".into());
        b.expires = Some("2028-01-01T00:00:00Z".into());
        let c = diff(&a, &b, &[]);
        let get = |f: &str| c.iter().find(|x| x.field == f).unwrap();
        assert_eq!(get("nameservers").severity, "high");
        assert_eq!(get("nameservers").added, vec![json!("ns1.evil.example")]);
        assert_eq!(get("status").severity, "high");
        assert!(get("status").note.as_ref().unwrap().contains("transfer lock removed"));
        assert_eq!(get("registrar.name").severity, "high");
        assert_eq!(get("expires").note.as_deref(), Some("renewed"));
        assert_eq!(worst(&c), "high");
        assert!(
            diff(&a, &b, &["nameservers".into(), "status".into(), "registrar".into(), "expires".into()]).is_empty()
        );
    }

    #[test]
    fn live_sections_ignore_churn_and_toggles() {
        use crate::model::{Dns, Hosting, Tls};
        let with_live = |ip: &str, sha: &str| {
            let mut r = rec();
            r.dns = Some(Dns {
                a: vec![ip.into()],
                ns: vec!["a.ns.net".into()],
                hosting: vec![Hosting {
                    asn: Some(13335),
                    name: Some("CF".into()),
                    ips: vec![ip.into()],
                    ..Default::default()
                }],
                ..Default::default()
            });
            r.tls = Some(Tls {
                issuer: Some("CA".into()),
                sha256: Some(sha.into()),
                valid: Some(true),
                ..Default::default()
            });
            r
        };
        let (a, b) = (with_live("1.1.1.1", "aa"), with_live("1.0.0.1", "bb"));
        assert!(diff(&a, &b, &[]).is_empty(), "{:?}", diff(&a, &b, &[]));
        assert!(diff(&rec(), &a, &[]).is_empty(), "turning --dns/--tls on is not a change");
        let mut flaky = with_live("1.1.1.1", "aa");
        flaky.dns.as_mut().unwrap().error = Some("request timed out".into());
        flaky.dns.as_mut().unwrap().ns.clear();
        assert!(diff(&a, &flaky, &[]).is_empty(), "transient failure is not a change");
        let mut gone = flaky.clone();
        gone.dns.as_mut().unwrap().error = Some("NXDOMAIN: the domain does not exist in DNS".into());
        assert_eq!(diff(&a, &gone, &[]).iter().find(|c| c.field == "dns.error").unwrap().severity, "high");
        let mut moved = with_live("1.1.1.1", "aa");
        moved.dns.as_mut().unwrap().hosting[0].asn = Some(16509);
        assert_eq!(diff(&a, &moved, &[])[0].field, "dns.hosting");
    }

    #[test]
    fn intervals() {
        assert_eq!(parse_interval("6h").unwrap().as_secs(), 21600);
        assert!(parse_interval("10s").is_err());
    }
}
