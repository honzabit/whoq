//! Offline test harness: a fake RDAP HTTP server, a fake port-43 server
//! (IANA referrals, a legacy registry, Team Cymru bulk) and a fake DNS server, plus a
//! sandboxed cache/state dir with a seeded IANA bootstrap pointing at the fake server.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone)]
pub struct Resp {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone)]
pub struct Http {
    pub base: String,
    routes: Arc<Mutex<HashMap<String, Resp>>>,
    pub hits: Arc<Mutex<Vec<String>>>,
}

impl Http {
    fn start() -> Http {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let http = Http { base, routes: Default::default(), hits: Default::default() };
        let h = http.clone();
        thread::spawn(move || {
            for conn in l.incoming().flatten() {
                let h = h.clone();
                thread::spawn(move || h.serve(conn));
            }
        });
        http
    }

    fn serve(&self, mut conn: TcpStream) {
        let mut reader = BufReader::new(conn.try_clone().unwrap());
        let mut first = String::new();
        if reader.read_line(&mut first).is_err() {
            return;
        }
        loop {
            let mut l = String::new();
            if reader.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                break;
            }
        }
        let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
        self.hits.lock().unwrap().push(path.clone());
        let resp = self.routes.lock().unwrap().get(&path).cloned().unwrap_or(Resp {
            status: 404,
            body: r#"{"errorCode":404,"title":"Not Found"}"#.into(),
            headers: vec![],
        });
        let mut head = format!(
            "HTTP/1.1 {} X\r\nContent-Type: application/rdap+json\r\nContent-Length: {}\r\nConnection: close\r\n",
            resp.status,
            resp.body.len()
        );
        for (k, v) in &resp.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        let _ = conn.write_all(head.as_bytes());
        let _ = conn.write_all(resp.body.as_bytes());
    }

    pub fn route(&self, path: &str, status: u16, body: &str) {
        self.route_with(path, status, body, vec![]);
    }

    pub fn route_with(&self, path: &str, status: u16, body: &str, headers: Vec<(&str, &str)>) {
        let headers = headers.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        self.routes.lock().unwrap().insert(path.into(), Resp { status, body: body.into(), headers });
    }

    pub fn hits_for(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }
}

pub struct Whois {
    pub addr: String,
    pub queries: Arc<Mutex<Vec<String>>>,
}

impl Whois {
    fn start(handler: impl Fn(&str) -> String + Send + Sync + 'static) -> Whois {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let queries: Arc<Mutex<Vec<String>>> = Default::default();
        let q = queries.clone();
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for mut conn in l.incoming().flatten() {
                let (q, handler) = (q.clone(), handler.clone());
                thread::spawn(move || {
                    // Client sends the query terminated by CRLF, then waits for EOF.
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    while conn.read(&mut byte).unwrap_or(0) == 1 {
                        buf.push(byte[0]);
                        if buf.ends_with(b"\r\n") {
                            break;
                        }
                    }
                    let query = String::from_utf8_lossy(&buf).trim_end().to_string();
                    q.lock().unwrap().push(query.clone());
                    let _ = conn.write_all(handler(&query).as_bytes());
                });
            }
        });
        Whois { addr, queries }
    }

    pub fn all(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }
}

// ---------------- fake DNS (UDP, authoritative-style answers) ----------------

#[derive(Clone, Debug)]
pub enum Rr {
    A(&'static str),
    Aaaa(&'static str),
    Ns(&'static str),
    Ptr(&'static str),
    Mx(u16, &'static str),
    Txt(&'static str),
    Caa(&'static str, &'static str),
}

impl Rr {
    fn rtype(&self) -> u16 {
        match self {
            Rr::A(_) => 1,
            Rr::Ns(_) => 2,
            Rr::Ptr(_) => 12,
            Rr::Mx(..) => 15,
            Rr::Txt(_) => 16,
            Rr::Aaaa(_) => 28,
            Rr::Caa(..) => 257,
        }
    }
    fn rdata(&self) -> Vec<u8> {
        match self {
            Rr::A(ip) | Rr::Aaaa(ip) => match ip.parse::<IpAddr>().unwrap() {
                IpAddr::V4(v) => v.octets().to_vec(),
                IpAddr::V6(v) => v.octets().to_vec(),
            },
            Rr::Ns(n) | Rr::Ptr(n) => encode_name(n),
            Rr::Mx(p, n) => [p.to_be_bytes().to_vec(), encode_name(n)].concat(),
            Rr::Txt(t) => t.as_bytes().chunks(255).flat_map(|c| [vec![c.len() as u8], c.to_vec()].concat()).collect(),
            Rr::Caa(tag, v) => [vec![0, tag.len() as u8], tag.as_bytes().to_vec(), v.as_bytes().to_vec()].concat(),
        }
    }
}

fn encode_name(n: &str) -> Vec<u8> {
    let mut out = vec![];
    for l in n.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        out.push(l.len() as u8);
        out.extend(l.as_bytes());
    }
    out.push(0);
    out
}

#[derive(Clone)]
pub struct Dns {
    pub addr: String,
    zone: Arc<Mutex<HashMap<String, Vec<Rr>>>>,
    pub queries: Arc<Mutex<Vec<(String, u16)>>>,
}

impl Dns {
    fn start() -> Dns {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let dns = Dns { addr, zone: Default::default(), queries: Default::default() };
        let d = dns.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf) {
                if let Some(resp) = d.answer(&buf[..n]) {
                    let _ = sock.send_to(&resp, peer);
                }
            }
        });
        dns
    }

    /// Add records for `name` (lowercase, no trailing dot).
    pub fn add(&self, name: &str, rrs: Vec<Rr>) {
        self.zone.lock().unwrap().entry(name.to_ascii_lowercase()).or_default().extend(rrs);
    }

    pub fn asked(&self, name: &str) -> bool {
        self.queries.lock().unwrap().iter().any(|(n, _)| n == name)
    }

    fn answer(&self, q: &[u8]) -> Option<Vec<u8>> {
        // header(12) + qname labels + qtype + qclass
        let mut i = 12;
        let mut labels = vec![];
        while i < q.len() && q[i] != 0 {
            let l = q[i] as usize;
            labels.push(String::from_utf8_lossy(q.get(i + 1..i + 1 + l)?).to_ascii_lowercase());
            i += 1 + l;
        }
        let qtype = u16::from_be_bytes([*q.get(i + 1)?, *q.get(i + 2)?]);
        let qend = i + 5;
        let name = labels.join(".");
        self.queries.lock().unwrap().push((name.clone(), qtype));

        let zone = self.zone.lock().unwrap();
        let exists = zone.contains_key(&name);
        let answers: Vec<Rr> =
            zone.get(&name).map(|v| v.iter().filter(|r| r.rtype() == qtype).cloned().collect()).unwrap_or_default();
        let rcode = if exists { 0 } else { 3 }; // NXDOMAIN for names with no records at all
        let mut out = vec![q[0], q[1], 0x81 | (q[2] & 0x01), 0x80 | rcode, 0, 1];
        out.extend((answers.len() as u16).to_be_bytes());
        out.extend([0, 0, 0, 0]); // no authority / additional
        out.extend(&q[12..qend]);
        for rr in answers {
            out.extend([0xc0, 0x0c]); // pointer to the question name
            out.extend(rr.rtype().to_be_bytes());
            out.extend([0, 1, 0, 0, 0, 60]); // class IN, TTL 60
            let rd = rr.rdata();
            out.extend((rd.len() as u16).to_be_bytes());
            out.extend(rd);
        }
        Some(out)
    }
}

pub fn fixture_raw(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn cymru_line(ip: &str) -> Option<&'static str> {
    Some(match ip {
        "8.8.8.8" => {
            "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE - Google LLC, US"
        }
        "8.8.4.4" => {
            "15169   | 8.8.4.4          | 8.8.4.0/24          | US | arin     | 1992-12-01 | GOOGLE - Google LLC, US"
        }
        "1.1.1.1" => {
            "13335   | 1.1.1.1          | 1.1.1.0/24          | AU | apnic    | 2011-08-11 | CLOUDFLARENET - Cloudflare, Inc., US"
        }
        _ => return None,
    })
}

fn whois_handler(q: &str) -> String {
    if let Some(body) = q.strip_prefix("begin\nverbose\n") {
        let mut out = String::from("Bulk mode; whois.cymru.com [2026-11-14 00:00:00 +0000]\n");
        for ip in body.lines().filter(|l| *l != "end") {
            out.push_str(cymru_line(ip).unwrap_or("NA      | 0.0.0.0 | NA | | other | | NA"));
            out.push('\n');
        }
        return out;
    }
    match q {
        // whois.iana.org referral for the legacy TLD (no RDAP in bootstrap)
        "legacy" => "domain:       LEGACY\nwhois:        whois.nic.legacy\n".into(),
        "test" => "domain:       TEST\n".into(),
        "old.legacy" => fixture_raw("legacy_registered.txt"),
        "nope.legacy" => fixture_raw("legacy_notfound.txt"),
        _ => "No match.\n".into(),
    }
}

pub struct Env {
    pub dir: PathBuf,
    pub http: Http,
    pub whois: Whois,
    pub dns: Dns,
}

impl Env {
    pub fn new(name: &str) -> Env {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("whoq-it-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("cache/bootstrap")).unwrap();
        let http = Http::start();
        let whois = Whois::start(whois_handler);
        let b = &http.base;
        let boot = |file: &str, services: String| {
            std::fs::write(
                dir.join("cache/bootstrap").join(file),
                format!(r#"{{"version":"1.0","publication":"2026-11-14T00:00:00Z","services":{services}}}"#),
            )
            .unwrap();
        };
        boot("dns.json", format!(r#"[[["test"],["{b}/registry/"]]]"#));
        boot("ipv4.json", format!(r#"[[["198.51.100.0/24"],["{b}/rir/"]]]"#));
        boot("ipv6.json", "[]".into());
        boot("asn.json", format!(r#"[[["64496-64511"],["{b}/rir/"]]]"#));
        Env { dir, http, whois, dns: Dns::start() }
    }

    /// Fixture with `{{BASE}}` replaced by the fake server's URL.
    pub fn fixture(&self, name: &str) -> String {
        fixture_raw(name).replace("{{BASE}}", &self.http.base)
    }

    pub fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_whoq"));
        cmd.args(args)
            .env("WHOQ_CACHE_DIR", self.dir.join("cache"))
            .env("WHOQ_STATE_DIR", self.dir.join("state"))
            .env("WHOQ_WHOIS_ADDR", &self.whois.addr)
            .env("WHOQ_DNS_SERVER", &self.dns.addr)
            .env("NO_COLOR", "1")
            .env_remove("WHOQ_WEBHOOK")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn whoq");
        {
            let mut si = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                si.write_all(s.as_bytes()).unwrap();
            }
        }
        child.wait_with_output().unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!("invalid JSON ({e}):\nstdout: {}\nstderr: {}", stdout(o), String::from_utf8_lossy(&o.stderr))
    })
}

pub fn ndjson(o: &Output) -> Vec<serde_json::Value> {
    stdout(o).lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
}
