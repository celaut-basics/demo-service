use warp::Filter;
use reqwest::Client;

#[tokio::main]
async fn main() {
    // Define the route that checks the connection to google.es
    let check_connection = warp::path::end().map(|| async {
        // Create an HTTP client
        let client = Client::new();
        
        // Attempt to send a GET request to google.es
        match client.get("https://www.google.es").send().await {
            Ok(response) => {
                if response.status().is_success() {
                    "Connection to google.es successful".to_string()
                } else {
                    format!("Connection to google.es failed: {}", response.status())
                }
            }
            Err(e) => format!("Error connecting to google.es: {}", e),
        }
    });

    // Start the server on port 3030
    warp::serve(check_connection).run(([0, 0, 0, 0], 3030)).await;
}