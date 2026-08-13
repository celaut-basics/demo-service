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
        format!(
            "{{\"service\":\"heavy\",\"cgroup_mem_max\":\"{}\",\"cgroup_mem_current\":\"{}\",\"proc_meminfo_memtotal_kb\":\"{}\"}}",
            cgroup_mem_max(), cgroup_mem_current(), meminfo_total_kb()
        )
    });

    let routes = alloc_route.or(introspect_route).or(controlled_heavy_route);

    let port = 3030;
    println!("HEAVY Service listening on http://0.0.0.0:{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
