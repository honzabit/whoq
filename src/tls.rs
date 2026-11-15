//! Live TLS (`--tls`): connect to the host (port 443 unless the input names one) and read the
//! certificate it presents. Unlike `--dns` and `--mail`, this talks to the target's own server,
//! so it is visible to whoever runs it.
//!
//! Any certificate is accepted during the handshake, so expired, self-signed and mismatched
//! ones can still be described; validity is then checked separately against the Mozilla roots.
//! Certificate fields are attacker-controlled and are sanitized like registry data.

use crate::ctx::Ctx;
use crate::model::Tls;
use crate::sanitize::clean;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, ProtocolVersion, RootCertStore, SignatureScheme};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_NAMES: usize = 50;
/// A TLS handshake should never need long; don't let a tarpit hold a batch up.
const MAX_WAIT: Duration = Duration::from_secs(10);

pub struct Tools {
    connector: TlsConnector,
    verifier: Arc<WebPkiServerVerifier>,
}

/// Lets every certificate through the handshake (signatures over the handshake itself are
/// still checked), so a broken certificate can be read and then judged by `Tools::verifier`.
#[derive(Debug)]
struct Inspect(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for Inspect {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Mozilla's roots, or only the PEM certificates in `WHOQ_TLS_CA` (tests, private CAs).
fn roots() -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    match std::env::var_os("WHOQ_TLS_CA").filter(|p| !p.is_empty()) {
        Some(path) => {
            let pem = std::fs::read(&path).map_err(|e| format!("WHOQ_TLS_CA: {e}"))?;
            for c in CertificateDer::pem_slice_iter(&pem) {
                let c = c.map_err(|e| format!("WHOQ_TLS_CA: {e}"))?;
                store.add(c).map_err(|e| format!("WHOQ_TLS_CA: {e}"))?;
            }
            if store.is_empty() {
                return Err("WHOQ_TLS_CA: no certificates found".into());
            }
        }
        None => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(store)
}

pub fn build_tools() -> Result<Tools, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots()?), provider.clone())
        .build()
        .map_err(|e| format!("tls: {e}"))?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Inspect(provider.signature_verification_algorithms)))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Tools { connector: TlsConnector::from(Arc::new(cfg)), verifier })
}

fn tools(ctx: &Ctx) -> Result<&Tools, String> {
    ctx.tls.get_or_init(build_tools).as_ref().map_err(Clone::clone)
}

/// Read and judge the certificate `host` presents on `port` (default 443).
pub async fn check(ctx: &Ctx, host: &str, port: Option<u16>) -> Tls {
    let port = port.unwrap_or(443);
    let mut t = Tls { host: Some(host.to_string()), port: (port != 443).then_some(port), ..Default::default() };
    let tools = match tools(ctx) {
        Ok(x) => x,
        Err(e) => {
            t.error = Some(e);
            return t;
        }
    };
    let name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => {
            t.error = Some(format!("{host}: {e}"));
            return t;
        }
    };
    let connect = async {
        let tcp = match &ctx.tls_addr {
            Some(addr) => TcpStream::connect(addr.as_str()).await,
            None => TcpStream::connect((host, port)).await,
        }?;
        let ip = tcp.peer_addr().ok().map(|a| a.ip());
        let stream = tools.connector.connect(name.clone(), tcp).await?;
        Ok::<_, std::io::Error>((ip, stream))
    };
    let (ip, stream) = match tokio::time::timeout(ctx.opts.timeout.min(MAX_WAIT), connect).await {
        Err(_) => {
            t.error = Some(format!("{host}:{port}: timed out"));
            return t;
        }
        Ok(Err(e)) => {
            t.error = Some(clean(&format!("{host}:{port}: {e}"), 300));
            return t;
        }
        Ok(Ok(x)) => x,
    };
    let (_, conn) = stream.get_ref();
    t.ip = ip.map(|i| i.to_string());
    t.protocol = conn.protocol_version().map(|v| match v {
        ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        other => format!("{other:?}"),
    });
    let chain: Vec<CertificateDer<'static>> =
        conn.peer_certificates().unwrap_or_default().iter().map(|c| c.clone().into_owned()).collect();
    drop(stream); // no request is sent; just close
    let Some(leaf) = chain.first() else {
        t.error = Some("server sent no certificate".into());
        return t;
    };
    describe(&mut t, leaf);
    let verdict = tools.verifier.verify_server_cert(leaf, &chain[1..], &name, &[], UnixTime::now());
    t.valid = Some(verdict.is_ok());
    t.problem = verdict.err().map(|e| problem(&e, t.self_signed));
    t
}

fn problem(e: &rustls::Error, self_signed: bool) -> String {
    let rustls::Error::InvalidCertificate(c) = e else { return clean(&e.to_string(), 200) };
    match c {
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => "expired".into(),
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => "not valid yet".into(),
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            "not valid for this name".into()
        }
        CertificateError::UnknownIssuer if self_signed => "self-signed".into(),
        CertificateError::UnknownIssuer => "issuer not trusted (unknown CA or missing intermediate)".into(),
        CertificateError::Revoked => "revoked".into(),
        CertificateError::BadSignature => "bad signature".into(),
        other => clean(&format!("{other:?}"), 200),
    }
}

fn rfc3339(ts: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Fill the descriptive fields from the leaf certificate.
fn describe(t: &mut Tls, der: &[u8]) {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    t.sha256 = Some(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect());
    let Ok((_, c)) = x509_parser::parse_x509_certificate(der) else {
        t.error = Some("certificate could not be parsed".into());
        return;
    };
    let first = |it: &mut dyn Iterator<Item = &x509_parser::x509::AttributeTypeAndValue>| {
        it.next().and_then(|a| a.as_str().ok()).map(|s| clean(s, 200)).filter(|s| !s.is_empty())
    };
    t.subject = first(&mut c.subject().iter_common_name());
    let (org, cn) = (first(&mut c.issuer().iter_organization()), first(&mut c.issuer().iter_common_name()));
    t.issuer = match (org, cn) {
        (Some(o), Some(n)) if o != n => Some(format!("{o} ({n})")),
        (o, n) => o.or(n),
    };
    t.self_signed = c.subject() == c.issuer();
    let (nb, na) = (c.validity().not_before.timestamp(), c.validity().not_after.timestamp());
    t.not_before = rfc3339(nb);
    t.not_after = rfc3339(na);
    t.expires_in_days = Some((na - chrono::Utc::now().timestamp()).div_euclid(86400));
    if let Ok(Some(san)) = c.subject_alternative_name() {
        use x509_parser::extensions::GeneralName;
        for g in &san.value.general_names {
            match g {
                GeneralName::DNSName(n) => t.names.push(clean(n, 253).to_ascii_lowercase()),
                GeneralName::IPAddress(b) => {
                    let ip = match b.len() {
                        4 => <[u8; 4]>::try_from(*b).ok().map(IpAddr::from),
                        16 => <[u8; 16]>::try_from(*b).ok().map(IpAddr::from),
                        _ => None,
                    };
                    t.names.extend(ip.map(|i| i.to_string()));
                }
                _ => {}
            }
        }
    }
    if t.names.len() > MAX_NAMES {
        t.names_total = Some(t.names.len());
        t.names.truncate(MAX_NAMES);
    }
    use x509_parser::public_key::PublicKey;
    t.key = match c.public_key().parsed() {
        Ok(PublicKey::RSA(k)) => Some(format!("RSA {}", k.key_size())),
        Ok(PublicKey::EC(k)) => Some(format!("EC {}", k.key_size())),
        _ => match c.public_key().algorithm.algorithm.to_id_string().as_str() {
            "1.3.101.112" => Some("Ed25519".into()),
            "1.3.101.113" => Some("Ed448".into()),
            other => Some(other.to_string()),
        },
    };
}
