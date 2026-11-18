//! Rendering: human tables, JSON / NDJSON, field projection.

use crate::model::{Kind, Outcome, Record};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

pub const BRIEF_DOMAIN: &[&str] =
    &["result", "name", "registrar.name", "created", "expires", "nameservers", "signals", "error.code"];
pub const BRIEF_NET: &[&str] = &[
    "result",
    "name",
    "network.name",
    "network.cidr",
    "network.country",
    "network.org",
    "asn.name",
    "asn.org",
    "abuse_email",
    "error.code",
];

fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, k| cur.get(k)).filter(|v| !v.is_null())
}

/// Project a record onto dotted paths. Output keys are the paths themselves.
pub fn project(rec: &Record, fields: &[String]) -> Value {
    let full = serde_json::to_value(rec).unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("query".into(), full["query"].clone());
    for f in fields {
        if let Some(v) = get_path(&full, f) {
            out.insert(f.clone(), v.clone());
        }
    }
    Value::Object(out)
}

/// Extra brief fields when live DNS / mail was requested.
const BRIEF_DNS: &[&str] = &["dns.provider", "dns.hosting", "dns.error"];
const BRIEF_MAIL: &[&str] = &["mail.provider", "mail.null_mx", "mail.spf.all", "mail.dmarc.policy", "mail.error"];
const BRIEF_TLS: &[&str] =
    &["tls.valid", "tls.problem", "tls.issuer", "tls.not_after", "tls.expires_in_days", "tls.error"];

pub fn brief_fields(rec: &Record) -> Vec<String> {
    let list = if rec.kind == Kind::Domain { BRIEF_DOMAIN } else { BRIEF_NET };
    let mut v: Vec<String> = list.iter().map(|s| s.to_string()).collect();
    if rec.dns.is_some() {
        v.extend(BRIEF_DNS.iter().map(|s| s.to_string()));
    }
    if rec.mail.is_some() {
        v.extend(BRIEF_MAIL.iter().map(|s| s.to_string()));
    }
    if rec.tls.is_some() {
        v.extend(BRIEF_TLS.iter().map(|s| s.to_string()));
    }
    if rec.rdns.is_some() {
        v.push("rdns".into());
    }
    if rec.origin.is_some() {
        v.extend(["origin.asn", "origin.name", "origin.prefix", "origin.country", "origin.error"].iter().map(|s| s.to_string()));
    }
    v
}

// ---------- human output ----------

pub struct Style {
    pub color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
}

fn rel(s: &str) -> Option<(String, String)> {
    let d = DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&Utc);
    let days = (d - Utc::now()).num_days();
    let human = |n: i64| -> String {
        let n = n.abs();
        if n >= 730 {
            format!("{}y", n / 365)
        } else if n >= 60 {
            format!("{}mo", n / 30)
        } else {
            format!("{n}d")
        }
    };
    let r = if days >= 0 { format!("in {}", human(days)) } else { format!("{} ago", human(days)) };
    Some((d.format("%Y-%m-%d").to_string(), r))
}

pub fn pretty(rec: &Record, st: &Style) -> String {
    let mut out = String::new();
    let (badge, code) = match rec.result {
        Outcome::Registered => ("● registered", "33"),
        Outcome::Available => ("○ available", "1;32"),
        Outcome::Found => ("● found", "36"),
        Outcome::NotFound => ("○ not found", "35"),
        Outcome::Error => ("✕ error", "1;31"),
    };
    let title = match (&rec.name, &rec.unicode_name) {
        (Some(n), Some(u)) => format!("{u} ({n})"),
        (Some(n), None) => n.clone(),
        _ => rec.query.clone(),
    };
    out.push_str(&format!("{}  {}", st.bold(&title), st.paint(code, badge)));
    if rec.source.as_ref().is_some_and(|s| s.cached) {
        out.push_str(&st.dim("  (cached)"));
    }
    out.push('\n');

    let mut row = |k: &str, v: String| {
        if !v.is_empty() {
            out.push_str(&format!("  {}  {}\n", st.dim(&format!("{k:<12}")), v));
        }
    };

    if let Some(e) = &rec.error {
        row("Error", st.paint("31", &format!("{} — {}", e.code, e.message)));
    }
    if let Some(g) = &rec.registrar {
        let mut s = g.name.clone().unwrap_or_default();
        if let Some(id) = &g.iana_id {
            s.push_str(&st.dim(&format!("  IANA #{id}")));
        }
        row("Registrar", s);
    }
    let sig = rec.signals.clone().unwrap_or_default();
    for (label, val) in [
        ("Created", &rec.created),
        ("Updated", &rec.updated),
        ("Expires", &rec.expires),
        ("Transferred", &rec.transferred),
    ] {
        if let Some((d, r)) = val.as_deref().and_then(rel) {
            let mut r = st.dim(&format!("({r})"));
            if label == "Expires" && sig.expiring_soon == Some(true) {
                r = st.paint("1;31", &format!("({}) expiring soon", r));
            }
            if label == "Created" && sig.young == Some(true) {
                r = st.paint("1;31", "⚠ newly registered");
            }
            row(label, format!("{d}  {r}"));
        }
    }
    if !rec.status.is_empty() {
        row("Status", rec.status.join(", "));
    }
    if !rec.nameservers.is_empty() {
        row("Nameservers", rec.nameservers.join(", "));
    }
    if let Some(d) = rec.dnssec {
        row("DNSSEC", if d { st.paint("32", "signed") } else { st.dim("unsigned") });
    }
    if let Some(c) = &rec.registrant {
        let mut parts: Vec<String> =
            [&c.org, &c.name, &c.country, &c.email].iter().filter_map(|x| (*x).clone()).collect();
        if c.name.is_none() && c.org.is_none() {
            parts.insert(0, st.dim("redacted"));
        }
        row("Registrant", parts.join(" · "));
    } else if sig.privacy_redacted == Some(true) {
        row("Registrant", st.dim("redacted"));
    }
    if let Some(n) = &rec.network {
        let range = match (&n.start, &n.end) {
            (Some(a), Some(b)) => format!("{a} – {b}"),
            _ => String::new(),
        };
        row("Network", [n.name.clone(), n.net_type.clone()].into_iter().flatten().collect::<Vec<_>>().join("  "));
        row("Org", n.org.clone().unwrap_or_default());
        row("CIDR", n.cidr.join(", "));
        row("Range", range);
        row("Country", n.country.clone().unwrap_or_default());
    }
    if let Some(a) = &rec.asn {
        row("AS name", a.name.clone().unwrap_or_default());
        row("Org", a.org.clone().unwrap_or_default());
        row("Country", a.country.clone().unwrap_or_default());
    }
    if let Some(a) = &rec.abuse_email {
        row("Abuse", a.clone());
    }
    if let Some(o) = &rec.origin {
        let v = match (&o.error, o.asn) {
            (Some(e), _) => st.dim(e),
            (None, Some(n)) => {
                let tag = [o.prefix.clone(), o.country.clone()].into_iter().flatten().collect::<Vec<_>>().join(", ");
                format!("AS{n} {} {}", o.name.clone().unwrap_or_default(), st.dim(&format!("({tag})")))
            }
            _ => String::new(),
        };
        row("Origin AS", v);
    }
    if let Some(r) = &rec.rdns {
        let v = match (r.ptr.first(), r.verified, &r.error) {
            (_, _, Some(e)) => st.dim(&format!("lookup failed: {e}")),
            (Some(p), Some(true), _) => format!("{p}  {}", st.paint("32", "✓ forward-confirmed")),
            (Some(p), _, _) => format!("{p}  {}", st.paint("33", "? does not resolve back (unverified)")),
            (None, _, _) => st.dim("no PTR record"),
        };
        row("rDNS", v);
    }
    if let Some(d) = &rec.dns {
        if let Some(e) = &d.error {
            row("DNS", st.paint("31", e));
        } else {
            let hosting: Vec<String> = d
                .hosting
                .iter()
                .map(|h| {
                    let tag =
                        [h.asn.map(|a| format!("AS{a}")), h.country.clone()].into_iter().flatten().collect::<Vec<_>>();
                    format!("{} {}", h.name.clone().unwrap_or_default(), st.dim(&format!("({})", tag.join(", "))))
                })
                .collect();
            let addrs: Vec<&String> = d.a.iter().chain(&d.aaaa).collect();
            if addrs.is_empty() {
                row("Hosting", st.paint("33", "no A/AAAA records (does not resolve)"));
            } else {
                let more = if addrs.len() > 2 { format!(" +{}", addrs.len() - 2) } else { String::new() };
                let ips = addrs.iter().take(2).map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                let host = match &d.host {
                    Some(h) if Some(h) != rec.name.as_ref() => format!("{h}: "),
                    _ => String::new(),
                };
                let who = if hosting.is_empty() { String::new() } else { format!("{}  ", hosting.join(" + ")) };
                row("Hosting", format!("{who}{}", st.dim(&format!("{host}{ips}{more}"))));
            }
            if let Some(p) = &d.provider {
                let p = if p.contains("parking") { st.paint("1;33", &format!("⚠ {p}")) } else { p.clone() };
                row("DNS", p);
            }
            if !d.caa.is_empty() {
                // Show which CAs may issue; the full records (with parameters) are in JSON.
                let mut cas: Vec<&str> = d
                    .caa
                    .iter()
                    .filter_map(|c| c.strip_prefix("issue ").or_else(|| c.strip_prefix("issuewild ")))
                    .map(|v| v.split(';').next().unwrap_or("").trim())
                    .filter(|v| !v.is_empty())
                    .collect();
                cas.sort();
                cas.dedup();
                let v = if cas.is_empty() { d.caa.join(", ") } else { format!("only {}", cas.join(", ")) };
                row("CAA", v);
            }
        }
    }
    if let Some(e) = rec.mail.as_ref().and_then(|m| m.error.as_ref()) {
        row("Mail", st.paint("31", e));
    } else if let Some(m) = &rec.mail {
        let mx = if m.null_mx {
            st.dim("null MX: accepts no mail")
        } else if m.mx.is_empty() {
            st.dim("no MX records")
        } else {
            let first = &m.mx[0].host;
            let more = if m.mx.len() > 1 { format!(" +{}", m.mx.len() - 1) } else { String::new() };
            match &m.provider {
                Some(p) => format!("{p}  {}", st.dim(&format!("{first}{more}"))),
                None => format!("{first}{more}"),
            }
        };
        row("Mail", mx);
        if let Some(spf) = &m.spf {
            let all = spf.all.clone().unwrap_or_else(|| "no all".into());
            let all = if all == "+all" { st.paint("1;31", "+all (anyone may send)") } else { all };
            let inc = if spf.includes.is_empty() {
                String::new()
            } else {
                st.dim(&format!("  include {}", spf.includes.join(", ")))
            };
            let err = spf.error.as_ref().map(|e| st.paint("31", &format!("  ⚠ {e}"))).unwrap_or_default();
            row("SPF", format!("{all}{inc}{err}"));
        } else {
            row("SPF", st.dim("none"));
        }
        let dmarc = match m.dmarc.as_ref().and_then(|d| d.policy.clone()) {
            Some(p) if p != "none" => st.paint("32", &p),
            Some(p) => st.paint("33", &format!("{p}  (monitoring only: spoofed mail is delivered)")),
            None => st.paint("33", "none  (spoofed mail is not rejected)"),
        };
        row("DMARC", dmarc);
        if !m.dkim_selectors.is_empty() {
            row("DKIM", format!("{}  {}", m.dkim_selectors.join(", "), st.dim("(common selectors probed)")));
        }
        let extras: Vec<&str> = [(m.mta_sts, "MTA-STS"), (m.tls_rpt, "TLS-RPT"), (m.bimi, "BIMI")]
            .into_iter()
            .filter_map(|(on, n)| on.then_some(n))
            .collect();
        if !extras.is_empty() {
            row("Mail extras", extras.join(", "));
        }
    }
    if let Some(t) = &rec.tls {
        let target = match t.port {
            Some(p) => format!("{}:{p}", t.host.as_deref().unwrap_or("")),
            None => t.host.clone().unwrap_or_default(),
        };
        if let Some(e) = &t.error {
            row("TLS", st.paint("31", e));
        } else {
            let verdict = match (t.valid, &t.problem) {
                (Some(true), _) => st.paint("32", "✓ valid"),
                (_, Some(p)) => st.paint("1;31", &format!("✗ {p}")),
                _ => st.paint("1;31", "✗ invalid"),
            };
            let proto = t.protocol.as_deref().map(|p| format!(" · {p}")).unwrap_or_default();
            row("TLS", format!("{verdict}  {}", st.dim(&format!("{target}{proto}"))));
            if let Some(i) = &t.issuer {
                row("Issuer", if t.self_signed { format!("{i}  {}", st.dim("(self-signed)")) } else { i.clone() });
            }
            if let (Some(na), Some(d)) = (&t.not_after, t.expires_in_days) {
                let date = na.get(..10).unwrap_or(na);
                let rel = match d {
                    d if d < 0 => st.paint("1;31", &format!("expired {}d ago", -d)),
                    d if d < 14 => st.paint("33", &format!("in {d}d")),
                    d => st.dim(&format!("in {d}d")),
                };
                row("Cert expires", format!("{date}  {rel}"));
            }
            if !t.names.is_empty() {
                let shown = t.names.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
                let total = t.names_total.unwrap_or(t.names.len());
                let more = if total > 6 { st.dim(&format!(" +{}", total - 6)) } else { String::new() };
                row("Cert names", format!("{shown}{more}"));
            }
        }
    }
    if let Some(s) = &rec.source {
        let srv = s.servers.first().cloned().unwrap_or_default();
        row("Source", st.dim(&format!("{} · {}", s.protocol, srv)));
    }
    out
}

pub fn pretty_projection(v: &Value, st: &Style) -> String {
    let mut out = String::new();
    if let Value::Object(m) = v {
        out.push_str(&st.bold(m.get("query").and_then(|q| q.as_str()).unwrap_or("")));
        out.push('\n');
        for (k, val) in m.iter().filter(|(k, _)| *k != "query") {
            let s = match val {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            out.push_str(&format!("  {}  {}\n", st.dim(&format!("{k:<16}")), s));
        }
    }
    out
}

fn show(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(show).collect::<Vec<_>>().join(", "),
        Value::Null => "∅".into(),
        other => other.to_string(),
    }
}

/// Human rendering of a `whoq watch` event.
pub fn pretty_event(e: &Value, st: &Style) -> String {
    let name = e["name"].as_str().unwrap_or("?");
    let sev_color = |s: &str| match s {
        "high" => "1;31",
        "medium" => "33",
        _ => "2",
    };
    let mut out = String::new();
    match e["event"].as_str().unwrap_or("") {
        "baseline" => out.push_str(&format!("{}  {}\n", st.bold(name), st.dim("baseline recorded"))),
        "unchanged" => out.push_str(&format!("{}  {}\n", st.bold(name), st.dim("unchanged"))),
        "error" => out.push_str(&format!(
            "{}  {}\n",
            st.bold(name),
            st.paint("31", &format!("✕ {}", e["error"]["message"].as_str().unwrap_or("error")))
        )),
        "alert" => {
            let what = match e["alert"].as_str() {
                Some("expiring") => format!("⏰ expires in {} days ({})", e["expires_in_days"], show(&e["expires"])),
                Some("expired") => format!("⏰ EXPIRED {} days ago", -e["expires_in_days"].as_i64().unwrap_or(0)),
                Some("on_hold") => format!("⛔ on hold: {}", show(&e["status"])),
                Some("cert_expiring") => format!(
                    "🔒 certificate for {} expires in {} days ({})",
                    show(&e["host"]),
                    e["expires_in_days"],
                    show(&e["not_after"])
                ),
                Some("cert_expired") => format!(
                    "🔒 certificate for {} EXPIRED {} days ago",
                    show(&e["host"]),
                    -e["expires_in_days"].as_i64().unwrap_or(0)
                ),
                Some("cert_invalid") => {
                    format!("🔒 certificate for {} is invalid: {}", show(&e["host"]), show(&e["problem"]))
                }
                other => other.unwrap_or("alert").to_string(),
            };
            out.push_str(&format!("{}  {}\n", st.bold(name), st.paint("1;31", &what)));
        }
        "changed" => {
            let sev = e["severity"].as_str().unwrap_or("low");
            out.push_str(&format!(
                "{}  {}  {}\n",
                st.bold(name),
                st.paint(sev_color(sev), &format!("▲ changed ({sev})")),
                st.dim(&format!("since {}", show(&e["since"])))
            ));
            for c in e["changes"].as_array().into_iter().flatten() {
                let field = c["field"].as_str().unwrap_or("");
                let csev = c["severity"].as_str().unwrap_or("low");
                let label = st.paint(sev_color(csev), &format!("{field:<16}"));
                let note =
                    c["note"].as_str().map(|n| st.paint(sev_color(csev), &format!("  ← {n}"))).unwrap_or_default();
                let removed = c["removed"].as_array().filter(|a| !a.is_empty());
                let added = c["added"].as_array().filter(|a| !a.is_empty());
                if removed.is_some() || added.is_some() {
                    let mut first = true;
                    for (sign, list, color) in [("-", removed, "31"), ("+", added, "32")] {
                        if let Some(l) = list {
                            let lead = if first { label.clone() } else { " ".repeat(16) };
                            out.push_str(&format!(
                                "  {lead}  {}{}\n",
                                st.paint(color, &format!("{sign} {}", show(&Value::Array(l.clone())))),
                                if first { note.clone() } else { String::new() }
                            ));
                            first = false;
                        }
                    }
                } else {
                    out.push_str(&format!("  {label}  {} → {}{note}\n", st.dim(&show(&c["old"])), show(&c["new"])));
                }
            }
        }
        _ => {}
    }
    out
}
