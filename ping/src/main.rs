// src/main.rs — PING service, reworked into a NETWORK-ISOLATION probe.
//
// The service manifest (.service/service.json) declares an egress allow-list of
// ONLY google.com. This code, however, also attempts amazon.com — which is NOT
// declared. On an HONEST node the declared target must succeed while the
// UNDECLARED target must be blocked (the node only wires up egress for tags it
// granted, surfaced to us as NetworkResolution entries in /__config__ and
// served by the in-container DNS in dns.rs).
//
// Instead of printing prose, every target is turned into an explicit assertion
// and emitted as structured JSON: {target, declared, connected, status, verdict}.
// `declared` is derived from the node-provided allow-list (dns::resolved_tags),
// not hardcoded, so the probe generalises to whatever the node actually grants.
mod dns;

use warp::{Filter, Rejection, Reply};
use reqwest::Client;
use tokio::task;
use std::time::Duration;

struct Target { tag: &'static str, url: &'static str }

async fn check_site(client: &Client, url: &str) -> (bool, String) {
    match client.get(url).timeout(Duration::from_secs(8)).send().await {
        Ok(response) => (response.status().is_success(), format!("HTTP {}", response.status())),
        Err(e) => {
            let kind = if e.is_timeout() { "timeout" }
                       else if e.is_connect() { "connect_refused" }
                       else { "error" };
            (false, format!("{}: {}", kind, e))
        }
    }
}

fn json_escape(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "'") }

async fn network_isolation_probe() -> Result<impl Reply, Rejection> {
    // The node-provided allow-list (tags the node actually resolved for us).
    let resolved = dns::resolved_tags();

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new());

    let targets = [
        Target { tag: "google.com", url: "https://www.google.com" }, // declared in manifest
        Target { tag: "amazon.com", url: "https://www.amazon.com" }, // NOT declared → must be blocked
    ];

    let mut items: Vec<String> = Vec::new();
    let mut honest = true;

    for t in targets.iter() {
        let declared = resolved.contains(t.tag)
            || resolved.contains(&format!("www.{}", t.tag));
        let (connected, status) = check_site(&client, t.url).await;

        // Honesty assertion for this target.
        let verdict = match (declared, connected) {
            (true, true)   => "honest_allowed",   // declared + reachable  -> correct
            (false, false) => "honest_blocked",   // undeclared + blocked  -> correct
            (false, true)  => { honest = false; "DISHONEST_LEAK" },   // undeclared but reachable -> node leaked egress
            (true, false)  => { honest = false; "BROKEN_DENIED" },    // declared but blocked -> node shortchanged access
        };

        items.push(format!(
            "{{\"target\":\"{}\",\"declared\":{},\"connected\":{},\"status\":\"{}\",\"verdict\":\"{}\"}}",
            t.tag, declared, connected, json_escape(&status), verdict
        ));
    }

    let mut tags: Vec<String> = resolved.into_iter().collect();
    tags.sort();
    let tags_json = tags.iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(",");

    let body = format!(
        "{{\"probe\":\"network_isolation\",\"resolved_tags\":[{}],\"targets\":[{}],\"honest\":{}}}",
        tags_json, items.join(","), honest
    );

    Ok(warp::reply::with_header(body, "content-type", "application/json"))
}

#[tokio::main]
async fn main() {
    // Start the in-container DNS server that serves the node-granted tags.
    task::spawn_blocking(|| { dns::main(); });

    let route = warp::path::end().and_then(network_isolation_probe);

    println!("PING network-isolation probe on http://0.0.0.0:3030");
    println!("GET / -> asserts declared egress (google) succeeds and undeclared (amazon) is blocked.");
    warp::serve(route).run(([0, 0, 0, 0], 3030)).await;
}
