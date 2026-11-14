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

fn key(rec: &Record) -> String {
    rec.name
        .as_deref()
        .unwrap_or(&rec.query)
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

pub fn load(dir: &Path, rec: &Record) -> Option<Snapshot> {
    let bytes = std::fs::read(dir.join(format!("{}.json", key(rec)))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save(dir: &Path, snap: &Snapshot) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join(format!("{}.json", key(&snap.record)));
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
    let mut out = Map::new();
    flatten(&v, "", &mut out);
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
        f if f.starts_with("registrant.") || f.starts_with("registrar.") => ("medium", None),
        _ => ("low", None),
    }
}

pub fn diff(old: &Record, new: &Record, ignore: &[String]) -> Vec<Change> {
    let (a, b) = (stable(old), stable(new));
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let mut out = vec![];
    for k in keys {
        if ignore.iter().any(|i| k == i || k.starts_with(&format!("{i}."))) {
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
    pub show_unchanged: bool,
}

/// Process one fresh record: compare with its snapshot, update state, return events.
pub fn process(rec: Record, o: &RoundOpts) -> Vec<Value> {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let name = rec.name.clone().unwrap_or(rec.query.clone());
    let base = |event: &str| json!({ "event": event, "at": now, "query": rec.query, "name": name });

    if rec.result == Outcome::Error {
        // Never overwrite a good snapshot with a failed lookup.
        let mut e = base("error");
        e["error"] = serde_json::to_value(&rec.error).unwrap_or(Value::Null);
        return vec![e];
    }

    let prev = load(o.dir, &rec);
    let mut alerts_sent = prev.as_ref().map(|p| p.alerts.clone()).unwrap_or_default();
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
            let id = format!("{kind}:{exp}");
            if !alerts_sent.contains(&id) {
                let mut e = base("alert");
                e["alert"] = json!(kind);
                e["severity"] = json!("high");
                e["expires"] = json!(exp);
                e["expires_in_days"] = json!(days);
                events.push(e);
                alerts_sent.push(id);
            }
        }
    }
    if rec.signals.as_ref().and_then(|s| s.on_hold) == Some(true) {
        let id = format!("on_hold:{}", rec.status.join(","));
        if !alerts_sent.contains(&id) {
            let mut e = base("alert");
            e["alert"] = json!("on_hold");
            e["severity"] = json!("high");
            e["status"] = json!(rec.status);
            events.push(e);
            alerts_sent.push(id);
        }
    }
    alerts_sent.retain(|a| a.ends_with(rec.expires.as_deref().unwrap_or("\0")) || a.starts_with("on_hold:"));

    let save_err = base("error");
    let snap = Snapshot { record: rec, seen_at: now, alerts: alerts_sent };
    if let Err(e) = save(o.dir, &snap) {
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
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = num.parse().map_err(|_| format!("invalid interval: {s} (use e.g. 30m, 6h, 1d)"))?;
    if n * mult < 60 {
        return Err("interval must be at least 60s (be kind to registries)".into());
    }
    Ok(std::time::Duration::from_secs(n * mult))
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
    fn intervals() {
        assert_eq!(parse_interval("6h").unwrap().as_secs(), 21600);
        assert!(parse_interval("10s").is_err());
    }
}
