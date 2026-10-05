// src/main.rs — SHAREFS-DENIED service, the child that must NOT be able to run.
//
// Its manifest (.service/service.json) declares a `guest` directory,
// /mnt/not-granted, for a share tag its parent does not export. The share
// invariant is that only the exporter's direct children can ever attach to what it
// exports, and that a service declaring an inherited directory it was never granted
// cannot run at all: the node must refuse the LAUNCH, before anything is spent.
//
// So on an HONEST node this code never executes. The orchestrator asks for this
// service on purpose and expects the node to say no.
//
// If a node does launch it, this service exists to show what the node did about the
// share, so that the orchestrator can tell "the node mounted something it had not
// granted" (the guest mount plan lists the path) from "the node launched it with
// nothing mounted" (which on its own does not say whether the declaration was ever
// there).
//
//   GET /whoami   identity.
//   GET /plan     the guest mount plan the node injected, and any mount at the
//                 declared path.
use std::fs;
use warp::Filter;

// The directory the manifest declares as `guest`. The orchestrator recognises the
// node's refusal by this path, so the two must stay the same string.
const DENIED_MOUNT: &str = "/mnt/not-granted";
const MOUNT_PLAN: &str = "/.__nodo_virtiofs";
const PROC_MOUNTS: &str = "/proc/mounts";

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

fn mount_line(proc_mounts: &str, mount_point: &str) -> Option<String> {
    proc_mounts
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(mount_point))
        .map(|line| line.to_string())
}

/// What this guest was given for the share it was never granted, as JSON.
fn plan_report(plan: Option<&str>, proc_mounts: &str) -> String {
    let plan_json = match plan {
        Some(raw) => format!("{{\"present\":true,\"raw\":\"{}\"}}", json_escape(raw.trim())),
        None => "{\"present\":false,\"raw\":null}".to_string(),
    };
    let mount_json = match mount_line(proc_mounts, DENIED_MOUNT) {
        Some(line) => format!("\"{}\"", json_escape(&line)),
        None => "null".to_string(),
    };
    // Mounted if the plan names the path or /proc/mounts has it: either one means the
    // node attached something here.
    let in_plan = plan.map_or(false, |raw| raw.contains(DENIED_MOUNT));
    let mounted = in_plan || mount_line(proc_mounts, DENIED_MOUNT).is_some();
    format!(
        "{{\"probe\":\"shared_filesystem_denied\",\"service\":\"sharefs-denied\",\"path\":\"{}\",\"mount_plan\":{},\"mount\":{},\"mounted\":{}}}",
        DENIED_MOUNT, plan_json, mount_json, mounted
    )
}

#[tokio::main]
async fn main() {
    let whoami = warp::path("whoami").map(|| {
        warp::reply::with_header(
            "{\"service\":\"sharefs-denied\",\"identity\":\"celaut-demo-sharefs-denied\",\"role\":\"ungranted-share-probe\"}",
            "content-type", "application/json",
        )
    });

    let plan = warp::path("plan").map(|| {
        let plan = fs::read_to_string(MOUNT_PLAN).ok();
        let mounts = fs::read_to_string(PROC_MOUNTS).unwrap_or_default();
        warp::reply::with_header(plan_report(plan.as_deref(), &mounts), "content-type", "application/json")
    });

    println!("SHAREFS-DENIED on http://0.0.0.0:3030");
    println!("A node that honours the share invariant never starts this service.");
    warp::serve(whoami.or(plan)).run(([0, 0, 0, 0], 3030)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_mounted_is_reported_as_not_mounted() {
        let body = plan_report(None, "tmpfs /run tmpfs rw 0 0\n");
        assert!(body.contains("\"mounted\":false"), "{}", body);
        assert!(body.contains("\"mount_plan\":{\"present\":false,\"raw\":null}"), "{}", body);
    }

    #[test]
    fn a_plan_naming_the_path_means_the_node_attached_something() {
        let plan = "[{\"tag\":\"t\",\"path\":\"/mnt/not-granted\",\"ro\":false}]";
        let body = plan_report(Some(plan), "");
        assert!(body.contains("\"mounted\":true"), "{}", body);
    }

    #[test]
    fn a_mount_at_the_path_means_the_node_attached_something() {
        let body = plan_report(None, "tag0 /mnt/not-granted virtiofs rw 0 0\n");
        assert!(body.contains("\"mounted\":true"), "{}", body);
    }

    #[test]
    fn a_plan_for_some_other_path_is_not_a_mount_here() {
        let plan = "[{\"tag\":\"t\",\"path\":\"/mnt/other\",\"ro\":false}]";
        let body = plan_report(Some(plan), "");
        assert!(body.contains("\"mounted\":false"), "{}", body);
    }

    #[test]
    fn the_report_balances_its_braces() {
        let body = plan_report(Some("[]"), "tag0 /mnt/not-granted virtiofs rw 0 0\n");
        assert_eq!(body.matches('{').count(), body.matches('}').count(), "{}", body);
    }
}
