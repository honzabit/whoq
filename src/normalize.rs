//! Shared normalization: dates, status codes, redaction detection, signals.

use crate::model::{Record, Signals};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

/// Parse the zoo of date formats registries emit into RFC 3339 (UTC).
pub fn parse_date(s: &str) -> Option<String> {
    let s = s.trim();
    let try_one = |s: &str| -> Option<DateTime<Utc>> {
        if let Ok(d) = DateTime::parse_from_rfc3339(s) {
            return Some(d.with_timezone(&Utc));
        }
        for f in ["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S %z"] {
            if let Ok(d) = DateTime::parse_from_str(s, f) {
                return Some(d.with_timezone(&Utc));
            }
        }
        for f in [
            "%Y-%m-%dT%H:%M:%S%.fZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y.%m.%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d.%m.%Y %H:%M:%S",
        ] {
            if let Ok(d) = NaiveDateTime::parse_from_str(s, f) {
                return Some(d.and_utc());
            }
        }
        for f in
            ["%Y-%m-%d", "%Y.%m.%d", "%Y/%m/%d", "%d.%m.%Y", "%d-%b-%Y", "%d-%B-%Y", "%d/%m/%Y", "%Y%m%d", "%b %d %Y"]
        {
            if let Ok(d) = NaiveDate::parse_from_str(s, f) {
                return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
            }
        }
        None
    };
    let parsed = try_one(s)
        .or_else(|| {
            // "2026-08-13 (YYYY-MM-DD)", "2024-01-01 00:00:00 CLST", "13-Dec-2026 UTC"
            let mut toks = s.split_whitespace();
            let first = toks.next()?;
            let second = toks.next();
            second.and_then(|t| try_one(&format!("{first} {t}"))).or_else(|| try_one(first))
        })
        .or_else(|| try_one(s.trim_end_matches(" UTC").trim_end_matches(" GMT")))?;
    // Reject nonsense (some registries emit 0000-00-00 or year 1)
    if parsed.timestamp() < 0 {
        return None;
    }
    Some(parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// `clientTransferProhibited https://icann.org/epp#...` and `client transfer prohibited`
/// both become `client transfer prohibited`.
pub fn status(s: &str) -> String {
    let s = s.split_whitespace().filter(|t| !t.contains("://")).collect::<Vec<_>>().join(" ");
    let s = s.trim().trim_matches(|c| c == '(' || c == ')').to_string();
    if s.contains(' ') || s.contains('_') {
        return s.replace('_', " ").to_lowercase();
    }
    let mut out = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_uppercase() && prev_lower {
            out.push(' ');
        }
        prev_lower = c.is_lowercase();
        out.extend(c.to_lowercase());
    }
    out
}

const REDACTION_MARKERS: &[&str] = &[
    "redacted",
    "privacy",
    "data protected",
    "not disclosed",
    "withheld",
    "gdpr",
    "statutory masking",
    "contact privacy",
    "proxy",
    "please query the rdds service",
    "domains by proxy",
    "whoisguard",
    "not available from registry",
];

pub fn is_redacted(s: &str) -> bool {
    let l = s.to_lowercase();
    REDACTION_MARKERS.iter().any(|m| l.contains(m))
}

/// Keep a value only if it isn't a redaction placeholder.
pub fn real(s: Option<String>, redacted_flag: &mut bool) -> Option<String> {
    let s = s?.trim().to_string();
    if s.is_empty() {
        return None;
    }
    if is_redacted(&s) {
        *redacted_flag = true;
        return None;
    }
    Some(s)
}

/// `90`, `90s`, `30m`, `6h`, `2d`, `1w` -> Duration. A bare number is seconds; `0` is allowed.
pub fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86400),
        Some((i, 'w')) => (&s[..i], 7 * 86400),
        _ => (s, 1),
    };
    let n: u64 = num.trim().parse().map_err(|_| format!("invalid duration: {s:?} (use e.g. 90s, 30m, 6h, 2d, 1w)"))?;
    n.checked_mul(mult).map(std::time::Duration::from_secs).ok_or_else(|| format!("duration too large: {s}"))
}

pub fn dedupe(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

pub fn signals(r: &Record, privacy_redacted: Option<bool>) -> Option<Signals> {
    let now = Utc::now();
    let days = |s: &Option<String>| -> Option<i64> {
        let d = DateTime::parse_from_rfc3339(s.as_deref()?).ok()?;
        Some((d.with_timezone(&Utc) - now).num_days())
    };
    let age = days(&r.created).map(|d| -d);
    let exp = days(&r.expires);
    let xfer = days(&r.transferred).map(|d| -d);
    let on_hold = if r.status.is_empty() {
        None
    } else {
        Some(r.status.iter().any(|s| {
            s.contains("hold") || s.contains("pending delete") || s.contains("redemption") || s.contains("inactive")
        }))
    };
    let dns = r.dns.as_ref().filter(|d| d.error.is_none());
    let mail = r.mail.as_ref().filter(|m| m.error.is_none());
    let sig = Signals {
        resolves: dns.map(|d| !d.a.is_empty() || !d.aaaa.is_empty()),
        parked: dns.filter(|d| !d.ns.is_empty()).map(|d| d.provider.as_deref().is_some_and(|p| p.contains("parking"))),
        accepts_mail: mail.map(|m| !m.mx.is_empty() && !m.null_mx),
        spoofable: mail.map(|m| m.dmarc.as_ref().and_then(|d| d.policy.as_deref()).is_none_or(|p| p == "none")),
        age_days: age,
        expires_in_days: exp,
        young: age.map(|a| a < 30),
        expiring_soon: exp.map(|e| (0..30).contains(&e)),
        expired: exp.map(|e| e < 0),
        recently_transferred: xfer.map(|x| x < 60),
        privacy_redacted,
        on_hold,
    };
    (sig != Signals::default()).then_some(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(parse_date("1995-08-14T04:00:00Z").unwrap(), "1995-08-14T04:00:00Z");
        assert_eq!(parse_date("2024-01-02T03:04:05.123Z").unwrap(), "2024-01-02T03:04:05Z");
        assert_eq!(parse_date("13-Dec-2026").unwrap(), "2026-12-13T00:00:00Z");
        assert_eq!(parse_date("2001/01/31").unwrap(), "2001-01-31T00:00:00Z");
        assert_eq!(parse_date("2020-05-05 (YYYY-MM-DD)").unwrap(), "2020-05-05T00:00:00Z");
        assert_eq!(parse_date("2024-12-11T10:00:00+01:00").unwrap(), "2024-12-11T09:00:00Z");
        assert!(parse_date("before Aug-1996").is_none());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0").unwrap().as_secs(), 0);
        assert_eq!(parse_duration("3600").unwrap().as_secs(), 3600);
        assert_eq!(parse_duration("90s").unwrap().as_secs(), 90);
        assert_eq!(parse_duration("30m").unwrap().as_secs(), 1800);
        assert_eq!(parse_duration("2d").unwrap().as_secs(), 172800);
        assert_eq!(parse_duration("1w").unwrap().as_secs(), 604800);
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("-5m").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn statuses() {
        assert_eq!(
            status("clientTransferProhibited https://icann.org/epp#clientTransferProhibited"),
            "client transfer prohibited"
        );
        assert_eq!(status("client delete prohibited"), "client delete prohibited");
        assert_eq!(status("ok"), "ok");
        assert_eq!(status("ACTIVE"), "active");
        assert_eq!(status("serverHold"), "server hold");
    }
}
