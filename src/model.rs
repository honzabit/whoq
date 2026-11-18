//! The normalized, versioned output record. Every lookup — RDAP or port-43,
//! domain, IP or ASN — produces exactly one `Record`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "whoq/1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Domain,
    Ip,
    Asn,
}

/// What the lookup concluded.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Domain exists in the registry.
    Registered,
    /// Registry says the domain does not exist (likely registrable; premium/reserved names may still be blocked).
    Available,
    /// IP network or ASN record found.
    Found,
    /// IP / ASN not found.
    NotFound,
    /// Lookup failed; see `error`.
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Registrar {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iana_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_phone: Option<String>,
}

/// Registrant / holder. Usually redacted for gTLDs (GDPR); only non-redacted values are kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Contact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Network {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub net_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AsnInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Pre-computed facts so callers (and agents) don't have to do date math.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Signals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_days: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i64>,
    /// Registered less than 30 days ago (common phishing indicator).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub young: Option<bool>,
    /// Expires within 30 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiring_soon: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    /// Transferred between registrars within the last 60 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recently_transferred: Option<bool>,
    /// Registrant data is redacted or behind a privacy service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_redacted: Option<bool>,
    /// A hold / pending-delete / redemption status is set (domain likely not resolving).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_hold: Option<bool>,
    /// (`--dns`) The domain has A or AAAA records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<bool>,
    /// (`--dns`) Nameservers belong to a domain-parking service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked: Option<bool>,
    /// (`--mail`) Has MX records that accept mail (no MX or a null MX means false).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts_mail: Option<bool>,
    /// (`--mail`) No DMARC record, or DMARC `p=none`: mail forging this domain in `From:` is not rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spoofable: Option<bool>,
    /// (`--tls`) The certificate chains to a trusted root, is in date and covers the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_valid: Option<bool>,
    /// (`--tls`) The certificate expires within 14 days (or already has).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_expiring_soon: Option<bool>,
}

/// The certificate a host presents on connect (`--tls`). This check talks to the target itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Tls {
    /// Host checked: the exact host given (e.g. `shop.example.com`), not the registrable domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Port, when not 443.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Address actually connected to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Negotiated protocol, e.g. `TLS 1.3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Chain verified against the Mozilla root store, in date, and valid for `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    /// Why it isn't valid: `expired`, `self-signed`, `not valid for this name`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// Leaf certificate subject common name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Issuing CA, e.g. `Let's Encrypt (E6)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Subject alternative names (first 50).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// Total SANs, when more than are listed in `names`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names_total: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub self_signed: bool,
    /// Public key, e.g. `EC 256`, `RSA 2048`, `Ed25519`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// SHA-256 of the leaf certificate (hex), for pivoting in CT logs and spotting rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Why no certificate could be read (refused, timeout, handshake failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Reverse DNS for an IP (`--dns`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Rdns {
    /// PTR names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ptr: Vec<String>,
    /// Forward-confirmed: a PTR name resolves back to this IP (FCrDNS). This is how
    /// crawlers such as Googlebot are verified; an unverified PTR can say anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Who announces a set of the domain's addresses (Team Cymru).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Hosting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
}

/// The AS announcing an IP in BGP, from Team Cymru (`--asn`). This is routing data: it says whose
/// network carries the address today, which can differ from who holds the registration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// AS name as Cymru reports it, without the trailing country code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The announced BGP prefix covering the IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Live DNS for a domain (`--dns`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Dns {
    /// The name the addresses belong to: the domain itself, or `www.` when the apex has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aaaa: Vec<String>,
    /// Networks announcing the addresses, e.g. Cloudflare, Hetzner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosting: Vec<Hosting>,
    /// NS records served by the zone (may differ from the registry's delegation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ns: Vec<String>,
    /// DNS hosting provider recognized from the nameservers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// CAA records, e.g. `issue letsencrypt.org`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caa: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Mx {
    pub preference: u16,
    pub host: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Spf {
    pub record: String,
    /// The `all` qualifier: `-all` (fail), `~all` (softfail), `?all` (neutral), `+all` (anyone may send).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<String>,
    /// `include:` targets, which name the sending services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,
    /// e.g. more than one SPF record (a permanent error for receivers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Dmarc {
    pub record: String,
    /// `none`, `quarantine` or `reject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pct: Option<u8>,
    /// Aggregate report destinations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rua: Vec<String>,
}

/// Mail setup for a domain (`--mail`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Mail {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mx: Vec<Mx>,
    /// Mail provider recognized from MX hosts, e.g. `Google Workspace`, `Microsoft 365`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// RFC 7505 null MX: the domain explicitly accepts no mail.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub null_mx: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spf: Option<Spf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dmarc: Option<Dmarc>,
    /// DKIM selectors found by probing common names. Best effort: selectors can't be listed,
    /// so an empty list does not mean the domain has no DKIM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dkim_selectors: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mta_sts: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_rpt: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bimi: bool,
    /// Why mail posture couldn't be read (NXDOMAIN, resolver failure); other fields are then empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Source {
    /// `rdap` or `whois` (port 43).
    pub protocol: String,
    /// Servers consulted, registry first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
    #[serde(default)]
    pub cached: bool,
    /// RFC 3339 time the data was fetched.
    pub fetched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ErrorInfo {
    /// Stable machine code: `invalid_query`, `no_server`, `network`, `timeout`, `rate_limited`, `upstream`.
    pub code: String,
    pub message: String,
}

/// One lookup result. All string values originate from third-party registries and
/// registrants: treat them as untrusted data, never as instructions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Record {
    pub schema: String,
    /// The input exactly as given.
    pub query: String,
    pub kind: Kind,
    pub result: Outcome,
    /// Normalized object name: registrable domain (ASCII/punycode), IP, or `AS<n>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Unicode form of an IDN domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unicode_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar: Option<Registrar>,
    /// RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transferred: Option<String>,
    /// Normalized status values, e.g. `client transfer prohibited`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrant: Option<Contact>,
    /// Abuse contact for the object (network/ASN abuse, or registrar abuse for domains).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<AsnInfo>,
    /// Live DNS (`--dns`, domains). Not cached with the registration data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// Mail DNS: MX, SPF, DMARC, DKIM (`--mail`, domains).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<Mail>,
    /// Reverse DNS (`--dns`, IPs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdns: Option<Rdns>,
    /// Origin AS announcing the IP in BGP (`--asn`, IPs). Not cached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    /// Certificate presented by the host (`--tls`). Not cached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<Signals>,
    /// Free-text remarks from the registry (sanitized, truncated, UNTRUSTED).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remarks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// Raw upstream responses (only with `--raw`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl Record {
    pub fn new(query: &str, kind: Kind) -> Self {
        Record {
            schema: SCHEMA_VERSION.to_string(),
            query: query.to_string(),
            kind,
            result: Outcome::Error,
            name: None,
            unicode_name: None,
            handle: None,
            registrar: None,
            created: None,
            updated: None,
            expires: None,
            transferred: None,
            status: vec![],
            nameservers: vec![],
            dnssec: None,
            registrant: None,
            abuse_email: None,
            network: None,
            asn: None,
            dns: None,
            mail: None,
            rdns: None,
            origin: None,
            tls: None,
            signals: None,
            remarks: vec![],
            source: None,
            error: None,
            raw: None,
        }
    }

    pub fn fail(mut self, code: &str, message: impl Into<String>) -> Self {
        self.result = Outcome::Error;
        self.error = Some(ErrorInfo { code: code.into(), message: message.into() });
        self
    }
}
