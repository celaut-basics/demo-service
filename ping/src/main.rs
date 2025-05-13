mod dns;

use warp::{Filter, Rejection, Reply};
use reqwest::Client;
use tokio::task;

/// Performs a GET request to the specified URL and returns a string with the result.
async fn check_site(client: &Client, url: &str, site_name: &str) -> String {
    match client.get(url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                format!("Connection to {} successful.", site_name)
            } else {
                format!("Connection to {} failed: {}.", site_name, response.status())
            }
        }
        Err(e) => format!("Error connecting to {}: {}.", site_name, e),
    }
}

/// Checks the connection to google.com and amazon.com.
async fn check_google_and_amazon_connections() -> Result<impl Reply, Rejection> {
    let client = Client::new();

    let google_url = "https://www.google.com";
    let amazon_url = "https://www.amazon.com";

    // Perform both checks concurrently
    let google_check_future = check_site(&client, google_url, "google.com");
    let amazon_check_future = check_site(&client, amazon_url, "amazon.com");

    // Wait for both tasks to complete
    let (google_result, amazon_result) = tokio::join!(google_check_future, amazon_check_future);

    // Combine the results into a single response
    let combined_response = format!(
        "Check result for google.com:\n{}\n\nCheck result for amazon.com:\n{}",
        google_result,
        amazon_result
    );

    Ok(combined_response)
}

#[tokio::main]
async fn main() {
    task::spawn_blocking(|| {
        dns::main();
    });

    let check_connections_route = warp::path::end()
        .and_then(check_google_and_amazon_connections);

    println!("Warp server started on http://0.0.0.0:3030");
    println!("Accessing the root path (/) will check the connection to google.com and amazon.com.");

    // Start the warp server.
    warp::serve(check_connections_route)
        .run(([0, 0, 0, 0], 3030))
        .await;
}