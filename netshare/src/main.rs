// src/main.rs — NETSHARE service, a member of a NETWORK share (#268).
//
// A network share is a directory that instances with no common parent share because
// they declare the same network (`Service.Network`) and the same share. This service
// declares the network `celaut-demo-netshare` with the selection key
// `group=${DEMO_NETSHARE_GROUP}`, and the directory /netshare as a share of that
// network (.service/service.json). So every instance launched with the same group is
// in one share, and an instance of another group is in another one.
//
// The orchestrator launches several of these as siblings: it is the parent of each one,
// but it does not export /netshare and it is not a member. Two members of one group
// must see what the other writes. A member of another group must not.
//
// This service only REPORTS what it observed. The orchestrator decides.
//
//   GET /write?name=<n>&nonce=<v>   write <v> to /netshare/<n>
//   GET /read?name=<n>              read /netshare/<n>
//   GET /whoami                     identity
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use warp::http::StatusCode;
use warp::Filter;

const SHARE: &str = "/netshare";
const GROUP_ENV: &str = "DEMO_NETSHARE_GROUP";
// The mount plan the node injects into a guest that has shares. Whether it is there at
// all tells the orchestrator whether the node was asked to mount anything here.
const MOUNT_PLAN: &str = "/.__nodo_virtiofs";
const PROC_MOUNTS: &str = "/proc/mounts";
const MAX_TOKEN_LEN: usize = 64;

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A name or a nonce chosen by the orchestrator. It becomes a file name, so refuse
/// anything that is not a plain token.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn context_json() -> String {
    let plan = match fs::read_to_string(MOUNT_PLAN) {
        Ok(raw) => format!("{{\"present\":true,\"raw\":\"{}\"}}", json_escape(raw.trim())),
        Err(_) => "{\"present\":false,\"raw\":null}".to_string(),
    };
    let mounts = fs::read_to_string(PROC_MOUNTS).unwrap_or_default();
    let mount = mounts
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(SHARE))
        .map_or("null".to_string(), |line| format!("\"{}\"", json_escape(line)));
    let group = std::env::var(GROUP_ENV)
        .map_or("null".to_string(), |g| format!("\"{}\"", json_escape(&g)));
    format!("\"mount_plan\":{},\"mount\":{},\"group\":{}", plan, mount, group)
}

fn io_error_json(e: &std::io::Error) -> String {
    format!(
        "\"error\":\"{}\",\"os_error\":{}",
        json_escape(&format!("{:?}: {}", e.kind(), e)),
        e.raw_os_error().map_or("null".to_string(), |c| c.to_string())
    )
}

fn write_file(name: &str, nonce: &str) -> String {
    // Written aside and renamed, so a reader never sees half a nonce.
    let tmp = Path::new(SHARE).join(format!(".{}.tmp", name));
    let result = fs::write(&tmp, nonce).and_then(|_| fs::rename(&tmp, Path::new(SHARE).join(name)));
    match result {
        Ok(()) => format!("{{\"service\":\"netshare\",\"ok\":true,{}}}", context_json()),
        Err(e) => format!(
            "{{\"service\":\"netshare\",\"ok\":false,{},{}}}",
            io_error_json(&e),
            context_json()
        ),
    }
}

fn read_file(name: &str) -> String {
    match fs::read_to_string(Path::new(SHARE).join(name)) {
        Ok(content) => format!(
            "{{\"service\":\"netshare\",\"present\":true,\"content\":\"{}\",{}}}",
            json_escape(content.trim_end()),
            context_json()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => format!(
            "{{\"service\":\"netshare\",\"present\":false,\"content\":null,{}}}",
            context_json()
        ),
        Err(e) => format!(
            "{{\"service\":\"netshare\",\"present\":false,\"content\":null,{},{}}}",
            io_error_json(&e),
            context_json()
        ),
    }
}

fn json_reply(body: String, status: StatusCode) -> warp::reply::WithStatus<warp::reply::WithHeader<String>> {
    warp::reply::with_status(
        warp::reply::with_header(body, "content-type", "application/json"),
        status,
    )
}

fn bad_request() -> warp::reply::WithStatus<warp::reply::WithHeader<String>> {
    json_reply(
        "{\"error\":\"name and nonce must be 1-64 characters of [A-Za-z0-9_-]\"}".to_string(),
        StatusCode::BAD_REQUEST,
    )
}

#[tokio::main]
async fn main() {
    let whoami = warp::path("whoami").map(|| {
        warp::reply::with_header(
            "{\"service\":\"netshare\",\"identity\":\"celaut-demo-netshare\",\"role\":\"network-share-member\"}",
            "content-type", "application/json",
        )
    });

    let write = warp::path("write")
        .and(warp::query::<HashMap<String, String>>())
        .map(|q: HashMap<String, String>| match (q.get("name"), q.get("nonce")) {
            (Some(name), Some(nonce)) if valid_token(name) && valid_token(nonce) => {
                json_reply(write_file(name, nonce), StatusCode::OK)
            }
            _ => bad_request(),
        });

    let read = warp::path("read")
        .and(warp::query::<HashMap<String, String>>())
        .map(|q: HashMap<String, String>| match q.get("name") {
            Some(name) if valid_token(name) => json_reply(read_file(name), StatusCode::OK),
            _ => bad_request(),
        });

    let routes = whoami.or(write).or(read);
    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await;
}
