// src/main.rs
use warp::Filter;
use std::time::Instant;
use std::vec;

// --- Function that consumes CPU (in a controlled manner) ---
// Calculates the Fibonacci number recursively.
// 'n' adjusted to be heavy, but not extreme.
fn controlled_heavy_fibonacci(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => controlled_heavy_fibonacci(n - 1) + controlled_heavy_fibonacci(n - 2),
    }
}

#[tokio::main]
async fn main() {
    println!("Starting the HEAVY service (CONTROLLED version)...");

    // Defines the main route ("/") that will do the heavy but limited work
    let controlled_heavy_route = warp::path::end().map(|| {
        println!("-> Request received! Performing heavy tasks (controlled)...");
        let process_start = Instant::now();

        // --- TASK 1: Consume Memory (Controlled) ---
        // Objective: Use ~50 MB of RAM per request (more reasonable than 100MB)
        let target_megabytes: usize = 50; // << ADJUSTED TO 50 MB
        let target_bytes: usize = target_megabytes * 1024 * 1024;

        println!("   1. Allocating ~{} MB of memory...", target_megabytes);
        let _memory_consumer: Vec<u8> = vec![0u8; target_bytes];
        println!("   -> Memory allocated.");
        // The memory will be automatically freed at the end of this `map` function.


        // --- TASK 2: Consume CPU (Controlled) ---
        // Objective: Make the CPU work, but for less time than before.
        let fibonacci_number: u64 = 38; // << ADJUSTED TO 38 (faster than 40)
        println!("   2. Calculating Fibonacci({}) (moderate CPU)...", fibonacci_number);
        let fib_result = controlled_heavy_fibonacci(fibonacci_number);
        println!("   -> Fibonacci calculation completed.");


        // --- End of process and Response ---
        let total_duration = process_start.elapsed();
        println!("-> Controlled tasks completed in {:?}", total_duration);

        format!(
            "HEAVY Service (Controlled) completed!\n\
             - Approximately {} MB of memory were used.\n\
             - Fibonacci({}) = {} was calculated.\n\
             - Total time: {:?}",
            target_megabytes,
            fibonacci_number,
            fib_result,
            total_duration
        )
    });

    // Starts the web server on port 3030
    let port = 3030;
    // Ensure the IP is 0.0.0.0 to accept external connections if needed,
    // or 127.0.0.1 for local only. 0.0.0.0 is more general.
    println!("HEAVY Service (Controlled) listening on http://0.0.0.0:{}", port);
    warp::serve(controlled_heavy_route).run(([0, 0, 0, 0], port)).await;
}