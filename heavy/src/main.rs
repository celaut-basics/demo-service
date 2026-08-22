// src/main.rs — HEAVY service, extended for the node-honesty verifier.
//
// Original behaviour (a controlled CPU+memory burst on "/") is preserved so the
// classic demo still works. Two probe endpoints are added:
//
//   GET /alloc/<mb>   Allocate <mb> MiB, TOUCH every page so the pages become
//                     resident (RSS), hold briefly, then free. Used by the
//                     orchestrator to ramp allocation toward the declared
//                     at_most.mem_limit (256 MiB) and observe where the node
//                     actually enforces the ceiling. If the node OOM-kills the
//                     process the HTTP connection drops — that is the signal.
//
//   GET /introspect   Report what the container actually sees (cgroup
//                     memory.max / memory.current and /proc/meminfo) so the
//                     provisioning-honesty probe can cross-check from inside a
//                     child microVM too.
use warp::Filter;
use std::time::{Instant, Duration};
use std::vec;
use std::thread::sleep;

// --- Function that consumes CPU (in a controlled manner) ---
fn controlled_heavy_fibonacci(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => controlled_heavy_fibonacci(n - 1) + controlled_heavy_fibonacci(n - 2),
    }
}

fn read_first_line(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
}

// cgroup v2 (memory.max) with a v1 fallback (memory.limit_in_bytes).
fn cgroup_mem_max() -> String {
    let v2 = read_first_line("/sys/fs/cgroup/memory.max");
    if v2 != "unavailable" { return v2; }
    read_first_line("/sys/fs/cgroup/memory/memory.limit_in_bytes")
}
fn cgroup_mem_current() -> String {
    let v2 = read_first_line("/sys/fs/cgroup/memory.current");
    if v2 != "unavailable" { return v2; }
    read_first_line("/sys/fs/cgroup/memory/memory.usage_in_bytes")
}
fn meminfo_total_kb() -> String {
    std::fs::read_to_string("/proc/meminfo").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("MemTotal"))
            .and_then(|l| l.split_whitespace().nth(1)).map(|v| v.to_string()))
        .unwrap_or_else(|| "unavailable".to_string())
}

// Effective memory ceiling: a cgroup when we run in a container, the guest's own
// RAM when we run in a microVM (cloud-hypervisor/qemu expose no cgroup at all,
// so reporting only cgroup values leaves the orchestrator blind on half the
// node's virtualizers). Returns (bytes, source) so the caller never has to guess
// which mechanism actually enforced the limit.
fn effective_mem_ceiling() -> (String, &'static str) {
    pick_mem_ceiling(&cgroup_mem_max(), &meminfo_total_kb())
}

// Split out from effective_mem_ceiling() so the decision can be unit-tested
// without a cgroup filesystem or a microVM to run inside.
fn pick_mem_ceiling(cgroup_max: &str, meminfo_kb: &str) -> (String, &'static str) {
    if cgroup_max != "unavailable" && !cgroup_max.is_empty() && cgroup_max != "max" {
        return (cgroup_max.to_string(), "cgroup.memory.max");
    }
    match meminfo_kb.parse::<u64>() {
        Ok(k) => ((k * 1024).to_string(), "proc.meminfo.MemTotal"),
        Err(_) => ("unavailable".to_string(), "unavailable"),
    }
}

#[tokio::main]
async fn main() {
    println!("Starting the HEAVY service (verifier-extended version)...");

    // Classic controlled burst on "/", now returning JSON.
    let controlled_heavy_route = warp::path::end().map(|| {
        let process_start = Instant::now();
        let target_megabytes: usize = 50;
        let target_bytes: usize = target_megabytes * 1024 * 1024;
        let mut memory_consumer: Vec<u8> = vec![0u8; target_bytes];
        // Touch pages so they are actually resident.
        let mut i = 0; while i < memory_consumer.len() { memory_consumer[i] = 1; i += 4096; }
        let fibonacci_number: u64 = 34;
        let fib_result = controlled_heavy_fibonacci(fibonacci_number);
        let total_duration = process_start.elapsed();
        drop(memory_consumer);
        format!(
            "{{\"service\":\"heavy\",\"allocated_mb\":{},\"fibonacci\":{{\"n\":{},\"result\":{}}},\"duration_ms\":{}}}",
            target_megabytes, fibonacci_number, fib_result, total_duration.as_millis()
        )
    });

    // /alloc/<mb> — allocate + touch <mb> MiB, hold briefly, report success.
    let alloc_route = warp::path!("alloc" / usize).map(|mb: usize| {
        println!("-> /alloc/{} : allocating and touching {} MiB...", mb, mb);
        let bytes: usize = mb.saturating_mul(1024 * 1024);
        let mut buf: Vec<u8> = vec![0u8; bytes];
        // Touch every 4 KiB page to force real residency (defeats lazy/overcommit).
        let mut i = 0usize;
        while i < buf.len() { buf[i] = (i % 251) as u8; i += 4096; }
        // Hold so the node's monitor/cgroup registers the RSS before we free.
        sleep(Duration::from_millis(300));
        let current = cgroup_mem_current();
        // Keep buf alive across the read above.
        let checksum = if buf.is_empty() { 0u8 } else { buf[0] };
        drop(buf);
        format!(
            "{{\"service\":\"heavy\",\"requested_mb\":{},\"touched\":true,\"ok\":true,\"cgroup_mem_current\":\"{}\",\"_c\":{}}}",
            mb, current, checksum
        )
    });

    // /introspect — what the container actually sees.
    let introspect_route = warp::path("introspect").map(|| {
        let (ceiling_bytes, ceiling_source) = effective_mem_ceiling();
        format!(
            "{{\"service\":\"heavy\",\"cgroup_mem_max\":\"{}\",\"cgroup_mem_current\":\"{}\",\"proc_meminfo_memtotal_kb\":\"{}\",\"ceiling_bytes\":\"{}\",\"ceiling_source\":\"{}\"}}",
            cgroup_mem_max(), cgroup_mem_current(), meminfo_total_kb(),
            ceiling_bytes, ceiling_source
        )
    });

    // Identity endpoint — lets the orchestrator confirm the requested dependency
    // (HEAVY) is the one that actually executed.
    let whoami_route = warp::path("whoami").map(|| {
        warp::reply::with_header(
            "{\"service\":\"heavy\",\"identity\":\"celaut-demo-heavy\",\"role\":\"memory-ceiling-probe\"}",
            "content-type", "application/json",
        )
    });

    let routes = whoami_route.or(alloc_route).or(introspect_route).or(controlled_heavy_route);

    let port = 3030;
    println!("HEAVY Service listening on http://0.0.0.0:{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

#[cfg(test)]
mod tests {
    use super::pick_mem_ceiling;

    #[test]
    fn container_prefers_the_cgroup() {
        let (bytes, source) = pick_mem_ceiling("268435456", "8000000");
        assert_eq!(bytes, "268435456");
        assert_eq!(source, "cgroup.memory.max");
    }

    #[test]
    fn microvm_falls_back_to_meminfo() {
        // A cloud-hypervisor/qemu guest exposes no cgroup at all, so reading only
        // cgroup files leaves the orchestrator blind on this virtualizer.
        let (bytes, source) = pick_mem_ceiling("unavailable", "938896");
        assert_eq!(bytes, "961429504"); // the live `witty-panda` figure
        assert_eq!(source, "proc.meminfo.MemTotal");
    }

    #[test]
    fn unlimited_cgroup_is_not_a_ceiling() {
        let (bytes, source) = pick_mem_ceiling("max", "938896");
        assert_eq!(bytes, "961429504");
        assert_eq!(source, "proc.meminfo.MemTotal");
    }

    #[test]
    fn nothing_readable_reports_unavailable_rather_than_guessing() {
        let (bytes, source) = pick_mem_ceiling("unavailable", "unavailable");
        assert_eq!(bytes, "unavailable");
        assert_eq!(source, "unavailable");
    }
}
