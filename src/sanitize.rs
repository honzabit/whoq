//! Registry and registrant data is attacker-controllable. Before it reaches a
//! terminal or an LLM context we strip control characters, ANSI escapes and
//! bidi overrides, collapse whitespace, and cap lengths.

use crate::model::Record;
use serde_json::Value;

const MAX_FIELD: usize = 256;
const MAX_REMARK: usize = 400;

fn is_dangerous(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Single-line clean: no control chars, whitespace collapsed, truncated.
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max + 4));
    let mut last_space = true;
    for c in s.chars() {
        let c = if c.is_whitespace() { ' ' } else { c };
        if is_dangerous(c) {
            continue;
        }
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        out.push(c);
    }
    let out = out.trim_end().to_string();
    truncate(out, max)
}

/// Multi-line clean for raw text: keeps `\n`, drops other controls.
pub fn clean_multiline(s: &str) -> String {
    s.chars().filter(|&c| c == '\n' || !is_dangerous(c)).map(|c| if c == '\t' { ' ' } else { c }).collect()
}

fn truncate(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

fn opt(o: &mut Option<String>) {
    if let Some(s) = o {
        let c = clean(s, MAX_FIELD);
        *o = (!c.is_empty()).then_some(c);
    }
}

fn vec(v: &mut Vec<String>, max: usize) {
    for s in v.iter_mut() {
        *s = clean(s, max);
    }
    v.retain(|s| !s.is_empty());
}

fn value(v: &mut Value) {
    match v {
        Value::String(s) => *s = clean_multiline(s),
        Value::Array(a) => a.iter_mut().for_each(value),
        Value::Object(o) => o.values_mut().for_each(value),
        _ => {}
    }
}

pub fn record(r: &mut Record) {
    opt(&mut r.name);
    opt(&mut r.unicode_name);
    opt(&mut r.handle);
    opt(&mut r.created);
    opt(&mut r.updated);
    opt(&mut r.expires);
    opt(&mut r.transferred);
    opt(&mut r.abuse_email);
    vec(&mut r.status, MAX_FIELD);
    vec(&mut r.nameservers, MAX_FIELD);
    vec(&mut r.remarks, MAX_REMARK);
    r.remarks.truncate(8);
    if let Some(x) = &mut r.registrar {
        opt(&mut x.name);
        opt(&mut x.iana_id);
        opt(&mut x.url);
        opt(&mut x.abuse_email);
        opt(&mut x.abuse_phone);
    }
    if let Some(x) = &mut r.registrant {
        opt(&mut x.name);
        opt(&mut x.org);
        opt(&mut x.state);
        opt(&mut x.country);
        opt(&mut x.email);
    }
    if let Some(x) = &mut r.network {
        opt(&mut x.start);
        opt(&mut x.end);
        vec(&mut x.cidr, MAX_FIELD);
        opt(&mut x.name);
        opt(&mut x.net_type);
        opt(&mut x.country);
        opt(&mut x.org);
        opt(&mut x.parent);
    }
    if let Some(x) = &mut r.asn {
        opt(&mut x.name);
        opt(&mut x.org);
        opt(&mut x.country);
    }
    if let Some(e) = &mut r.error {
        e.message = clean(&e.message, MAX_REMARK);
    }
    if let Some(raw) = &mut r.raw {
        value(raw);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escapes_and_bidi() {
        assert_eq!(clean("Evil\x1b[31mRed\x1b[0m\u{202E}cba", 100), "Evil[31mRed[0mcba");
        assert_eq!(clean("  a\n\n b\t c  ", 100), "a b c");
        assert_eq!(clean("abcdef", 3), "abc…");
    }
}
