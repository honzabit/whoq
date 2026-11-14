//! RDAP (RFC 9082/9083) client and JSON -> Record mapping.

use crate::ctx::{Ctx, LookupError};
use crate::model::{AsnInfo, Contact, Network, Record, Registrar};
use crate::normalize::{dedupe, parse_date, real, status};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, RETRY_AFTER};
use serde_json::Value;
use std::time::Duration;

pub enum Got {
    Found(Value),
    NotFound,
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

pub async fn get(ctx: &Ctx, url: &str) -> Result<Got, LookupError> {
    let host = reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let sem = ctx.host_limit(&host);
    let _permit = sem.acquire().await.expect("semaphore closed");

    let mut backoff = Duration::from_millis(600);
    for attempt in 0..3 {
        let last = attempt == 2;
        let resp = ctx.http.get(url).header(ACCEPT, "application/rdap+json, application/json;q=0.9").send().await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Err(LookupError::Timeout(format!("{host}: timed out"))),
            Err(e) if !last && (e.is_connect() || e.is_request()) => {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                continue;
            }
            Err(e) => return Err(LookupError::Network(format!("{host}: {}", chain(&e)))),
        };
        let st = resp.status();
        if st == StatusCode::NOT_FOUND {
            return Ok(Got::NotFound);
        }
        if st == StatusCode::TOO_MANY_REQUESTS || st == StatusCode::SERVICE_UNAVAILABLE {
            if last {
                return Err(LookupError::RateLimited(format!("{host}: HTTP {st}")));
            }
            let wait = resp
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.min(10)))
                .unwrap_or(backoff);
            tokio::time::sleep(wait).await;
            backoff *= 2;
            continue;
        }
        if !st.is_success() {
            return Err(LookupError::Upstream(format!("{host}: HTTP {st}")));
        }
        return resp
            .json::<Value>()
            .await
            .map(Got::Found)
            .map_err(|e| LookupError::Upstream(format!("{host}: invalid RDAP JSON: {}", chain(&e))));
    }
    unreachable!()
}

// ---------- jCard / entity helpers ----------

fn vcard<'a>(entity: &'a Value, prop: &str) -> Option<&'a Value> {
    entity["vcardArray"][1].as_array()?.iter().find(|p| p[0].as_str() == Some(prop))
}

fn vcard_text(entity: &Value, prop: &str) -> Option<String> {
    let p = vcard(entity, prop)?;
    let s = match &p[3] {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", "),
        _ => return None,
    };
    let s = s.trim_start_matches("mailto:").trim_start_matches("tel:").trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn vcard_country(entity: &Value) -> Option<String> {
    let adr = vcard(entity, "adr")?;
    if let Some(cc) = adr[1]["cc"].as_str() {
        return Some(cc.to_string());
    }
    adr[3].as_array()?.get(6)?.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

fn has_role(e: &Value, role: &str) -> bool {
    e["roles"].as_array().is_some_and(|r| r.iter().any(|x| x.as_str() == Some(role)))
}

/// All entities with a role, searching nested entities too.
fn entities<'a>(v: &'a Value, role: &str, out: &mut Vec<&'a Value>) {
    if let Some(list) = v["entities"].as_array() {
        for e in list {
            if has_role(e, role) {
                out.push(e);
            }
            entities(e, role, out);
        }
    }
}

fn first_entity<'a>(v: &'a Value, role: &str) -> Option<&'a Value> {
    let mut out = vec![];
    entities(v, role, &mut out);
    out.into_iter().next()
}

fn abuse_email(v: &Value) -> Option<String> {
    let mut out = vec![];
    entities(v, "abuse", &mut out);
    out.iter().find_map(|e| vcard_text(e, "email"))
}

fn str_of(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::to_string).filter(|s| !s.is_empty())
}

fn set<T>(slot: &mut Option<T>, val: Option<T>) {
    if slot.is_none() {
        *slot = val;
    }
}

fn apply_common(r: &mut Record, v: &Value, redacted: &mut bool) {
    set(&mut r.handle, str_of(v, "handle"));
    if let Some(events) = v["events"].as_array() {
        for e in events {
            let date = e["eventDate"].as_str().and_then(parse_date);
            match e["eventAction"].as_str().unwrap_or("") {
                "registration" => set(&mut r.created, date),
                "last changed" => set(&mut r.updated, date),
                "expiration" => set(&mut r.expires, date),
                "transfer" => set(&mut r.transferred, date),
                _ => {}
            }
        }
    }
    if r.status.is_empty()
        && let Some(st) = v["status"].as_array()
    {
        r.status = st.iter().filter_map(|s| s.as_str()).map(status).collect();
        dedupe(&mut r.status);
    }
    // RFC 9537 redaction markers
    if v["redacted"].as_array().is_some_and(|a| !a.is_empty()) {
        *redacted = true;
    }
    set(&mut r.abuse_email, abuse_email(v));
}

fn org_of(v: &Value, redacted: &mut bool) -> Option<String> {
    let e = first_entity(v, "registrant")?;
    real(vcard_text(e, "org").or_else(|| vcard_text(e, "fn")), redacted)
}

pub fn apply_domain(r: &mut Record, v: &Value, redacted: &mut bool) {
    apply_common(r, v, redacted);
    if r.unicode_name.is_none() {
        r.unicode_name = str_of(v, "unicodeName").filter(|u| Some(u.to_lowercase()) != r.name.clone());
    }
    if r.nameservers.is_empty()
        && let Some(ns) = v["nameservers"].as_array()
    {
        r.nameservers =
            ns.iter().filter_map(|n| n["ldhName"].as_str()).map(|s| s.trim_end_matches('.').to_lowercase()).collect();
        dedupe(&mut r.nameservers);
    }
    if r.dnssec.is_none() {
        r.dnssec = v["secureDNS"]["delegationSigned"].as_bool();
    }

    if let Some(e) = first_entity(v, "registrar") {
        let reg = r.registrar.get_or_insert_with(Registrar::default);
        set(&mut reg.name, vcard_text(e, "fn").or_else(|| str_of(e, "handle")));
        set(
            &mut reg.iana_id,
            e["publicIds"].as_array().and_then(|ids| {
                ids.iter()
                    .find(|i| i["type"].as_str().is_some_and(|t| t.contains("IANA")))
                    .and_then(|i| str_of(i, "identifier"))
            }),
        );
        set(&mut reg.url, vcard_text(e, "url"));
        let mut abuse = vec![];
        entities(e, "abuse", &mut abuse);
        if let Some(a) = abuse.first() {
            set(&mut reg.abuse_email, vcard_text(a, "email"));
            set(&mut reg.abuse_phone, vcard_text(a, "tel"));
        }
    }
    if r.abuse_email.is_none() {
        r.abuse_email = r.registrar.as_ref().and_then(|g| g.abuse_email.clone());
    }

    if let Some(e) = first_entity(v, "registrant") {
        let mut c = Contact {
            name: real(vcard_text(e, "fn"), redacted),
            org: real(vcard_text(e, "org"), redacted),
            country: vcard_country(e),
            email: real(vcard_text(e, "email"), redacted),
        };
        // a lone country is not a meaningful identity; still keep it (useful for jurisdiction)
        if c.name.is_some() && c.name == c.org {
            c.org = None;
        }
        if c != Contact::default() {
            let cur = r.registrant.get_or_insert_with(Contact::default);
            set(&mut cur.name, c.name);
            set(&mut cur.org, c.org);
            set(&mut cur.country, c.country);
            set(&mut cur.email, c.email);
        }
    }
}

pub fn apply_ip(r: &mut Record, v: &Value, redacted: &mut bool) {
    apply_common(r, v, redacted);
    let cidr = v["cidr0_cidrs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| {
                    let p = c["v4prefix"].as_str().or_else(|| c["v6prefix"].as_str())?;
                    Some(format!("{p}/{}", c["length"].as_u64()?))
                })
                .collect()
        })
        .unwrap_or_default();
    r.network = Some(Network {
        start: str_of(v, "startAddress"),
        end: str_of(v, "endAddress"),
        cidr,
        name: str_of(v, "name"),
        net_type: str_of(v, "type"),
        country: str_of(v, "country"),
        org: org_of(v, redacted),
        parent: str_of(v, "parentHandle"),
    });
    r.remarks = remarks(v);
}

pub fn apply_asn(r: &mut Record, v: &Value, redacted: &mut bool) {
    apply_common(r, v, redacted);
    r.asn = Some(AsnInfo {
        start: v["startAutnum"].as_u64().map(|n| n as u32),
        end: v["endAutnum"].as_u64().map(|n| n as u32),
        name: str_of(v, "name"),
        org: org_of(v, redacted),
        country: str_of(v, "country"),
    });
    r.remarks = remarks(v);
}

fn remarks(v: &Value) -> Vec<String> {
    v["remarks"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|rm| {
                    let d = rm["description"].as_array()?;
                    let text = d.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ");
                    (!text.trim().is_empty()).then_some(text)
                })
                .take(5)
                .collect()
        })
        .unwrap_or_default()
}

/// Registry responses for thin-ish TLDs link to the registrar's RDAP server,
/// which holds registrant/abuse data.
pub fn registrar_link(v: &Value, self_url: &str) -> Option<String> {
    let links = v["links"].as_array()?;
    links
        .iter()
        .filter(|l| l["rel"].as_str() == Some("related"))
        .filter(|l| l["type"].as_str().is_none_or(|t| t.contains("rdap")))
        .filter_map(|l| l["href"].as_str())
        // never downgrade https -> http
        .find(|h| {
            (h.starts_with("https://") || (h.starts_with("http://") && self_url.starts_with("http://")))
                && h.contains("/domain/")
                && !h.eq_ignore_ascii_case(self_url)
        })
        .map(str::to_string)
}
