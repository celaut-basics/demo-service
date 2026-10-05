// src/main.rs — SHAREFS service, a SHARED-FILESYSTEM probe (the granted child).
//
// The orchestrator exports a directory to its children, and this service declares
// two of them as `guest` in its manifest (.service/service.json):
//
//   /mnt/from-parent  the parent's /shared, read-write. It is mounted at a path
//                     DIFFERENT from the parent's own, so what matches the two sides
//                     is the share's tag, never where either one put it.
//   /mnt/readonly     the parent's /shared-ro, requested with access=ro.
//
// On an HONEST node, the parent's data is visible here, what we write is visible to
// the parent, and the read-only mount refuses writes.
//
// This service only REPORTS what it observed. It never decides a verdict: the
// orchestrator holds the other end of the share, so it can check the child's claims
// against what actually landed on disk instead of trusting them.
//
//   GET /probe?nonce=<n>   read the parent's nonce, write ours, attempt a write on
//                          the read-only mount, and return it all as JSON.
//   GET /whoami            identity, so the parent can tell the dependency it asked
//                          for is the one that ran.
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use warp::http::StatusCode;
use warp::Filter;

const SHARED_MOUNT: &str = "/mnt/from-parent";
const READONLY_MOUNT: &str = "/mnt/readonly";
// The mount plan the node injects into a guest that inherits shares (a JSON list of
// {tag, path, ro}). Whether it is there at all tells the parent whether the node was
// asked to mount anything for this instance.
const MOUNT_PLAN: &str = "/.__nodo_virtiofs";
const PROC_MOUNTS: &str = "/proc/mounts";

const PARENT_NONCE_FILE: &str = "parent_nonce";
const READONLY_SEED_FILE: &str = "ro_seed";
const CHILD_NONCE_FILE: &str = "child_nonce";
const READONLY_ATTEMPT_FILE: &str = "child_write_attempt";

const MAX_NONCE_LEN: usize = 64;

/// Escape a string for a JSON string literal.
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

/// A nonce is a token the orchestrator chose; refuse anything that is not one, since
/// it is written into a file name's neighbour and echoed into JSON.
fn valid_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= MAX_NONCE_LEN
        && nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// What an I/O error says, in a form the orchestrator can show: the kind and, when
/// the OS gave one, the errno (13 = EACCES, 30 = EROFS, 2 = ENOENT).
fn describe_io_error(e: &std::io::Error) -> (String, Option<i32>) {
    (format!("{:?}: {}", e.kind(), e), e.raw_os_error())
}

fn read_report(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(content) => format!("{{\"ok\":true,\"content\":\"{}\"}}", json_escape(content.trim_end())),
        Err(e) => {
            let (text, code) = describe_io_error(&e);
            format!(
                "{{\"ok\":false,\"missing\":{},\"error\":\"{}\",\"os_error\":{}}}",
                e.kind() == ErrorKind::NotFound,
                json_escape(&text),
                code.map_or("null".to_string(), |c| c.to_string())
            )
        }
    }
}

fn write_report(path: &Path, content: &str) -> String {
    match fs::write(path, content) {
        Ok(()) => "{\"ok\":true}".to_string(),
        Err(e) => {
            let (text, code) = describe_io_error(&e);
            format!(
                "{{\"ok\":false,\"error\":\"{}\",\"os_error\":{}}}",
                json_escape(&text),
                code.map_or("null".to_string(), |c| c.to_string())
            )
        }
    }
}

/// The /proc/mounts line whose mount point is `mount_point`, if any. That line says
/// what filesystem the guest really mounted there (virtiofs for a share), which is
/// evidence beside the data: an ordinary directory would hold a nonce too.
fn mount_line(proc_mounts: &str, mount_point: &str) -> Option<String> {
    proc_mounts
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(mount_point))
        .map(|line| line.to_string())
}

fn mount_json(proc_mounts: &str, mount_point: &str) -> String {
    match mount_line(proc_mounts, mount_point) {
        Some(line) => format!("\"{}\"", json_escape(&line)),
        None => "null".to_string(),
    }
}

fn mount_plan_json(plan_path: &Path) -> String {
    match fs::read_to_string(plan_path) {
        Ok(raw) => format!("{{\"present\":true,\"raw\":\"{}\"}}", json_escape(raw.trim())),
        Err(_) => "{\"present\":false,\"raw\":null}".to_string(),
    }
}

/// Run the whole observation against the given paths and render it as JSON.
fn probe(
    shared: &Path,
    readonly: &Path,
    plan: &Path,
    proc_mounts: &Path,
    nonce: &str,
) -> String {
    let mounts = fs::read_to_string(proc_mounts).unwrap_or_default();

    let parent_nonce = read_report(&shared.join(PARENT_NONCE_FILE));
    let child_write = write_report(&shared.join(CHILD_NONCE_FILE), nonce);

    let seed = read_report(&readonly.join(READONLY_SEED_FILE));
    let attempt_path = readonly.join(READONLY_ATTEMPT_FILE);
    let attempt = match fs::write(&attempt_path, nonce) {
        Ok(()) => "{\"succeeded\":true,\"error\":null,\"os_error\":null}".to_string(),
        Err(e) => {
            let (text, code) = describe_io_error(&e);
            format!(
                "{{\"succeeded\":false,\"error\":\"{}\",\"os_error\":{}}}",
                json_escape(&text),
                code.map_or("null".to_string(), |c| c.to_string())
            )
        }
    };

    format!(
        concat!(
            "{{\"probe\":\"shared_filesystem\",\"service\":\"sharefs\",",
            "\"mount_plan\":{},",
            "\"shared\":{{\"path\":\"{}\",\"mount\":{},\"parent_nonce\":{},\"child_write\":{}}},",
            "\"readonly\":{{\"path\":\"{}\",\"mount\":{},\"seed\":{},\"write_attempt\":{}}}}}"
        ),
        mount_plan_json(plan),
        json_escape(&shared.to_string_lossy()),
        mount_json(&mounts, &shared.to_string_lossy()),
        parent_nonce,
        child_write,
        json_escape(&readonly.to_string_lossy()),
        mount_json(&mounts, &readonly.to_string_lossy()),
        seed,
        attempt
    )
}

fn json_reply(body: String, status: StatusCode) -> impl warp::Reply {
    warp::reply::with_status(
        warp::reply::with_header(body, "content-type", "application/json"),
        status,
    )
}

#[tokio::main]
async fn main() {
    // Identity endpoint — lets the orchestrator confirm the requested dependency
    // (SHAREFS) is the one that actually executed.
    let whoami = warp::path("whoami").map(|| {
        warp::reply::with_header(
            "{\"service\":\"sharefs\",\"identity\":\"celaut-demo-sharefs\",\"role\":\"shared-filesystem-probe\"}",
            "content-type", "application/json",
        )
    });

    let probe_route = warp::path("probe")
        .and(warp::query::<HashMap<String, String>>())
        .map(|query: HashMap<String, String>| match query.get("nonce") {
            Some(nonce) if valid_nonce(nonce) => json_reply(
                probe(
                    Path::new(SHARED_MOUNT),
                    Path::new(READONLY_MOUNT),
                    Path::new(MOUNT_PLAN),
                    Path::new(PROC_MOUNTS),
                    nonce,
                ),
                StatusCode::OK,
            ),
            _ => json_reply(
                "{\"error\":\"nonce is required: 1-64 characters of [A-Za-z0-9_-]\"}".to_string(),
                StatusCode::BAD_REQUEST,
            ),
        });

    println!("SHAREFS shared-filesystem probe on http://0.0.0.0:3030");
    println!("GET /probe?nonce=<n> -> reports what this guest observed on the shares it inherited.");
    warp::serve(whoami.or(probe_route)).run(([0, 0, 0, 0], 3030)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A fresh scratch directory, since the crate takes no dependency for it.
    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sharefs-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn json_escape_covers_quotes_backslashes_and_control_characters() {
        assert_eq!(json_escape("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
    }

    #[test]
    fn nonce_is_a_short_plain_token() {
        assert!(valid_nonce("abc-123_DEF"));
        assert!(!valid_nonce(""));
        assert!(!valid_nonce("../etc/passwd"));
        assert!(!valid_nonce("a b"));
        assert!(!valid_nonce(&"x".repeat(MAX_NONCE_LEN + 1)));
        assert!(valid_nonce(&"x".repeat(MAX_NONCE_LEN)));
    }

    #[test]
    fn mount_line_matches_the_mount_point_field_only() {
        let mounts = "tag0 /mnt/from-parent virtiofs rw,relatime 0 0\n\
                      tmpfs /run tmpfs rw 0 0\n\
                      other /elsewhere/mnt/from-parent ext4 rw 0 0\n";
        assert_eq!(
            mount_line(mounts, "/mnt/from-parent").as_deref(),
            Some("tag0 /mnt/from-parent virtiofs rw,relatime 0 0")
        );
        assert_eq!(mount_line(mounts, "/mnt/readonly"), None);
    }

    #[test]
    fn probe_reads_the_parent_nonce_and_writes_the_childs() {
        let shared = scratch();
        let readonly = scratch();
        fs::write(shared.join(PARENT_NONCE_FILE), "parent-abc\n").unwrap();
        fs::write(readonly.join(READONLY_SEED_FILE), "seed-xyz").unwrap();

        let body = probe(
            &shared,
            &readonly,
            Path::new("/nonexistent/plan"),
            Path::new("/nonexistent/mounts"),
            "child-123",
        );

        assert!(body.contains("\"parent_nonce\":{\"ok\":true,\"content\":\"parent-abc\"}"), "{}", body);
        assert!(body.contains("\"child_write\":{\"ok\":true}"), "{}", body);
        assert!(body.contains("\"seed\":{\"ok\":true,\"content\":\"seed-xyz\"}"), "{}", body);
        assert_eq!(fs::read_to_string(shared.join(CHILD_NONCE_FILE)).unwrap(), "child-123");
        assert!(body.contains("\"mount_plan\":{\"present\":false,\"raw\":null}"), "{}", body);
    }

    #[test]
    fn probe_reports_a_missing_parent_nonce_as_missing_not_as_empty() {
        let shared = scratch();
        let readonly = scratch();
        let body = probe(
            &shared,
            &readonly,
            Path::new("/nonexistent/plan"),
            Path::new("/nonexistent/mounts"),
            "n1",
        );
        assert!(body.contains("\"parent_nonce\":{\"ok\":false,\"missing\":true"), "{}", body);
    }

    #[test]
    fn a_write_that_fails_is_reported_as_not_succeeded() {
        let shared = scratch();
        let missing_readonly = shared.join("does-not-exist");
        let body = probe(
            &shared,
            &missing_readonly,
            Path::new("/nonexistent/plan"),
            Path::new("/nonexistent/mounts"),
            "n1",
        );
        assert!(body.contains("\"write_attempt\":{\"succeeded\":false"), "{}", body);
    }

    #[test]
    fn mount_plan_is_returned_verbatim_when_present() {
        let dir = scratch();
        let plan = dir.join("plan");
        fs::write(&plan, "[{\"tag\":\"t\",\"path\":\"/mnt/from-parent\",\"ro\":false}]").unwrap();
        let json = mount_plan_json(&plan);
        assert!(json.starts_with("{\"present\":true,\"raw\":\""), "{}", json);
        assert!(json.contains("\\\"path\\\":\\\"/mnt/from-parent\\\""), "{}", json);
    }

    #[test]
    fn the_report_is_well_formed_json_shape() {
        let shared = scratch();
        let readonly = scratch();
        let body = probe(
            &shared,
            &readonly,
            Path::new("/nonexistent/plan"),
            Path::new("/nonexistent/mounts"),
            "n1",
        );
        // Braces balance: a hand-built JSON string is easy to get wrong.
        let open = body.matches('{').count();
        let close = body.matches('}').count();
        assert_eq!(open, close, "{}", body);
        assert!(body.starts_with('{') && body.ends_with('}'));
    }
}
