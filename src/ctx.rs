//! Shared runtime: HTTP client, per-host politeness limits, disk cache, errors.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;

/// Max concurrent requests to any single upstream host. Registries throttle hard.
const PER_HOST: usize = 2;

#[derive(Debug, Clone)]
pub enum LookupError {
    NoServer(String),
    Network(String),
    Timeout(String),
    RateLimited(String),
    Upstream(String),
}

impl LookupError {
    pub fn code(&self) -> &'static str {
        match self {
            LookupError::NoServer(_) => "no_server",
            LookupError::Network(_) => "network",
            LookupError::Timeout(_) => "timeout",
            LookupError::RateLimited(_) => "rate_limited",
            LookupError::Upstream(_) => "upstream",
        }
    }
    pub fn message(&self) -> &str {
        match self {
            LookupError::NoServer(m)
            | LookupError::Network(m)
            | LookupError::Timeout(m)
            | LookupError::RateLimited(m)
            | LookupError::Upstream(m) => m,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub timeout: Duration,
    pub cache_ttl: Duration,
    pub use_cache: bool,
    pub raw: bool,
    pub force_whois: bool,
    pub live: Live,
}

/// Live (uncached) checks layered on top of registration data.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Live {
    /// rdns for IPs; addresses, hosting network, NS provider and CAA for domains.
    pub dns: bool,
    /// MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI for domains.
    pub mail: bool,
}

impl Live {
    pub fn any(self) -> bool {
        self.dns || self.mail
    }
}

pub struct Ctx {
    pub http: reqwest::Client,
    pub opts: Options,
    pub cache_dir: Option<PathBuf>,
    /// `WHOQ_WHOIS_ADDR=host:port` routes every port-43 connection there (tests, proxies).
    pub whois_addr: Option<String>,
    hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
    pub(crate) bootstrap: tokio::sync::Mutex<HashMap<&'static str, Arc<crate::bootstrap::Registry>>>,
    pub(crate) whois_servers: Mutex<HashMap<String, Option<String>>>,
    pub(crate) resolver: tokio::sync::OnceCell<Result<crate::dns::Resolvers, String>>,
}

impl Ctx {
    pub fn new(opts: Options) -> anyhow::Result<Arc<Ctx>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("whoq/", env!("CARGO_PKG_VERSION")))
            .timeout(opts.timeout)
            .connect_timeout(Duration::from_secs(8))
            .https_only(false) // some bootstrap entries are http; we prefer https when offered
            .build()?;
        let cache_dir =
            std::env::var_os("WHOQ_CACHE_DIR").map(PathBuf::from).or_else(|| dirs::cache_dir().map(|d| d.join("whoq")));
        Ok(Arc::new(Ctx {
            http,
            opts,
            cache_dir,
            whois_addr: std::env::var("WHOQ_WHOIS_ADDR").ok().filter(|s| !s.is_empty()),
            hosts: Mutex::new(HashMap::new()),
            bootstrap: tokio::sync::Mutex::new(HashMap::new()),
            whois_servers: Mutex::new(HashMap::new()),
            resolver: tokio::sync::OnceCell::new(),
        }))
    }

    pub fn host_limit(&self, host: &str) -> Arc<Semaphore> {
        let mut m = self.hosts.lock().unwrap();
        m.entry(host.to_ascii_lowercase()).or_insert_with(|| Arc::new(Semaphore::new(PER_HOST))).clone()
    }

    fn cache_path(&self, bucket: &str, key: &str) -> Option<PathBuf> {
        let safe: String =
            key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
        Some(self.cache_dir.as_ref()?.join(bucket).join(format!("{safe}.json")))
    }

    /// Read a cached file if younger than `ttl` (or any age if `stale_ok`).
    pub async fn cache_get(&self, bucket: &str, key: &str, ttl: Duration, stale_ok: bool) -> Option<Vec<u8>> {
        let p = self.cache_path(bucket, key)?;
        let meta = tokio::fs::metadata(&p).await.ok()?;
        let age = SystemTime::now().duration_since(meta.modified().ok()?).unwrap_or_default();
        if age > ttl && !stale_ok {
            return None;
        }
        tokio::fs::read(&p).await.ok()
    }

    pub async fn cache_put(&self, bucket: &str, key: &str, data: &[u8]) {
        let Some(p) = self.cache_path(bucket, key) else { return };
        if let Some(dir) = p.parent() {
            let _ = tokio::fs::create_dir_all(dir).await;
        }
        // write-then-rename so concurrent readers never see a partial file
        let tmp = p.with_extension(format!("tmp{}", std::process::id()));
        if tokio::fs::write(&tmp, data).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, &p).await;
        }
    }
}
