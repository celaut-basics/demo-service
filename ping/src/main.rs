// src/main.rs — PING service, reworked into a NETWORK-ISOLATION probe.
//
// The service manifest (.service/service.json) declares an egress allow-list of
// ONLY google.com. This code also tries amazon.com, which is NOT declared. On an
// HONEST node the declared target must succeed while the UNDECLARED target must
// be blocked (the node only opens egress to the addresses of the tags it
// granted, surfaced to us as NetworkResolution entries in /__config__).
//
// The two targets are tested in two different ways, because only one of them
// can be reached by name:
//
// * google.com (declared): an HTTPS request to the name. The in-guest DNS in
//   dns.rs answers it with an address the node granted.
// * amazon.com (undeclared): a TCP connect to its addresses, which the parent
//   hands in through UNDECLARED_ADDRS. A request to the NAME would prove
//   nothing: dns.rs serves only granted tags, so the name never resolves, and
//   the request fails in the guest's own resolver before any packet reaches
//   the firewall that is under test. Without addresses the target is reported
//   UNTESTED, never "blocked".
//
// Every target is turned into an explicit assertion and emitted as structured
// JSON: {target, declared, method, connected, status, verdict}. `declared` is
// derived from the node-provided allow-list (dns::resolved_tags), not
// hardcoded, so the probe generalises to whatever the node actually grants.
mod dns;

use warp::{Filter, Rejection, Reply};
use reqwest::Client;
use tokio::task;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

// Comma-separated IPv4 addresses of the undeclared target, set by the parent
// (the verifier declares amazon.com itself, so the node resolves it there).
const UNDECLARED_ADDRS_ENV: &str = "UNDECLARED_ADDRS";
// A bare hostname tag opens ports 80 and 443; 443 is what a leak would use.
const UNDECLARED_PORT: u16 = 443;
// Bounds the probe: each address that is blocked costs one connect timeout.
const MAX_UNDECLARED_ADDRS: usize = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const DECLARED_TARGET: (&str, &str) = ("google.com", "https://www.google.com");
const UNDECLARED_TARGET: &str = "amazon.com";

async fn check_site(client: &Client, url: &str) -> (bool, String) {
    // Any HTTP answer proves the egress is open: a 4xx/5xx comes from the far
    // end too. Reading only 2xx as "connected" would hide a leak to a site
    // that answers bots with 503.
    match client.get(url).timeout(Duration::from_secs(8)).send().await {
        Ok(response) => (true, format!("HTTP {}", response.status())),
        Err(e) => {
            let kind = if e.is_timeout() { "timeout" }
                       else if e.is_connect() { "connect_refused" }
                       else { "error" };
            (false, format!("{}: {}", kind, e))
        }
    }
}

// Addresses that may stand for a destination on the open internet. Anything
// else (loopback, private, link-local, CGNAT, documentation, ...) cannot show
// whether the node leaks egress, so it is not tested.
fn is_public(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_private() || ip.is_link_local()
      || ip.is_broadcast() || ip.is_multicast() || ip.is_documentation()
      || (o[0] == 100 && (o[1] & 0xc0) == 64)   // 100.64.0.0/10, shared address space
      || o[0] == 0 || o[0] >= 240)
}

// The undeclared addresses to test: public, unique, not granted to this
// instance under another tag, and at most MAX_UNDECLARED_ADDRS of them.
fn undeclared_addresses(raw: &str, granted: &HashSet<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for part in raw.split(',') {
        if out.len() >= MAX_UNDECLARED_ADDRS {
            break;
        }
        if let Ok(ip) = part.trim().parse::<Ipv4Addr>() {
            if is_public(&ip) && !granted.contains(&ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

async fn tcp_reach(ip: Ipv4Addr, port: u16) -> Result<(), String> {
    let addr = SocketAddr::from((ip, port));
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{}: {}", addr, e)),
        Err(_) => Err(format!("{}: timeout", addr)),
    }
}

// The honesty assertion for one target, and whether it breaks isolation.
fn verdict(declared: bool, connected: bool) -> (&'static str, bool) {
    match (declared, connected) {
        (true, true)   => ("honest_allowed", true),   // declared + reachable  -> correct
        (false, false) => ("honest_blocked", true),   // undeclared + blocked  -> correct
        (false, true)  => ("DISHONEST_LEAK", false),  // undeclared but reachable -> node leaked egress
        (true, false)  => ("BROKEN_DENIED", false),   // declared but blocked -> node shortchanged access
    }
}

fn json_escape(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "'") }

fn json_str_list<T: ToString>(items: &[T]) -> String {
    items.iter()
        .map(|s| format!("\"{}\"", json_escape(&s.to_string())))
        .collect::<Vec<_>>()
        .join(",")
}

fn is_declared(resolved: &HashSet<String>, tag: &str) -> bool {
    resolved.contains(tag) || resolved.contains(&format!("www.{}", tag))
}

async fn network_isolation_probe() -> Result<impl Reply, Rejection> {
    // The node-provided allow-list (tags the node actually resolved for us).
    let resolved = dns::resolved_tags();

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut items: Vec<String> = Vec::new();
    let mut honest = true;

    // Declared target: by name, through the in-guest DNS.
    {
        let (tag, url) = DECLARED_TARGET;
        let declared = is_declared(&resolved, tag);
        let (connected, status) = check_site(&client, url).await;
        let (v, ok) = verdict(declared, connected);
        honest &= ok;
        items.push(format!(
            "{{\"target\":\"{}\",\"declared\":{},\"method\":\"https\",\"connected\":{},\"status\":\"{}\",\"verdict\":\"{}\"}}",
            tag, declared, connected, json_escape(&status), v
        ));
    }

    // Undeclared target: by address, straight at the node's firewall.
    {
        let tag = UNDECLARED_TARGET;
        let declared = is_declared(&resolved, tag);
        let raw = std::env::var(UNDECLARED_ADDRS_ENV).unwrap_or_default();
        let addresses = undeclared_addresses(&raw, &dns::granted_addresses());
        let mut reached: Vec<Ipv4Addr> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        for ip in &addresses {
            match tcp_reach(*ip, UNDECLARED_PORT).await {
                Ok(()) => reached.push(*ip),
                Err(e) => errors.push(e),
            }
        }
        let connected = !reached.is_empty();
        let (v, status) = if addresses.is_empty() {
            // Nothing to aim at: no claim either way.
            ("UNTESTED", format!("no public address of {} in {}", tag, UNDECLARED_ADDRS_ENV))
        } else {
            let (v, ok) = verdict(declared, connected);
            honest &= ok;
            let status = if connected {
                let ips: Vec<String> = reached.iter().map(|ip| ip.to_string()).collect();
                format!("tcp connected on port {} to {}", UNDECLARED_PORT, ips.join(", "))
            } else {
                errors.join("; ")
            };
            (v, status)
        };
        items.push(format!(
            "{{\"target\":\"{}\",\"declared\":{},\"method\":\"tcp_connect\",\"port\":{},\"addresses\":[{}],\"reached\":[{}],\"connected\":{},\"status\":\"{}\",\"verdict\":\"{}\"}}",
            tag, declared, UNDECLARED_PORT, json_str_list(&addresses), json_str_list(&reached),
            connected, json_escape(&status), v
        ));
    }

    let mut tags: Vec<String> = resolved.into_iter().collect();
    tags.sort();

    let body = format!(
        "{{\"probe\":\"network_isolation\",\"resolved_tags\":[{}],\"targets\":[{}],\"honest\":{}}}",
        json_str_list(&tags), items.join(","), honest
    );

    Ok(warp::reply::with_header(body, "content-type", "application/json"))
}

#[tokio::main]
async fn main() {
    // Start the in-container DNS server that serves the node-granted tags.
    task::spawn_blocking(|| { dns::main(); });

    // Identity endpoint — lets the orchestrator confirm the requested dependency
    // (PING) is the one that actually executed.
    let whoami = warp::path("whoami").map(|| {
        warp::reply::with_header(
            "{\"service\":\"ping\",\"identity\":\"celaut-demo-ping\",\"role\":\"network-isolation-probe\"}",
            "content-type", "application/json",
        )
    });

    let route = whoami.or(warp::path::end().and_then(network_isolation_probe));

    println!("PING network-isolation probe on http://0.0.0.0:3030");
    println!("GET / -> asserts declared egress (google) succeeds and undeclared (amazon) is blocked.");
    warp::serve(route).run(([0, 0, 0, 0], 3030)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_unique_ungranted_addresses_are_tested() {
        let granted: HashSet<Ipv4Addr> = vec!["52.94.236.248".parse().unwrap()].into_iter().collect();
        let got = undeclared_addresses(
            " 54.239.28.85,10.0.0.1,127.0.0.1,52.94.236.248,54.239.28.85,100.64.0.1,bogus,169.254.1.1",
            &granted,
        );
        assert_eq!(got, vec!["54.239.28.85".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn the_number_of_addresses_is_bounded() {
        let raw = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9";
        assert_eq!(undeclared_addresses(raw, &HashSet::new()).len(), MAX_UNDECLARED_ADDRS);
    }

    #[test]
    fn no_addresses_means_nothing_is_tested() {
        assert!(undeclared_addresses("", &HashSet::new()).is_empty());
    }

    #[test]
    fn the_verdict_matrix() {
        assert_eq!(verdict(true, true), ("honest_allowed", true));
        assert_eq!(verdict(false, false), ("honest_blocked", true));
        assert_eq!(verdict(false, true), ("DISHONEST_LEAK", false));
        assert_eq!(verdict(true, false), ("BROKEN_DENIED", false));
    }
}
