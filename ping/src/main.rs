use warp::{Filter, Rejection, Reply};
use reqwest::Client;
use std::convert::Infallible;

async fn check_google_connection() -> Result<impl Reply, Rejection> {
    let client = Client::new();

    let result_string = match client.get("https://www.google.com").send().await {
        Ok(response) => {
            if response.status().is_success() {
                "Connection to google.es successful".to_string()
            } else {
                format!("Connection to google.es failed: {}", response.status())
            }
        }
        Err(e) => format!("Error connecting to google.es: {}", e),
    };

    Ok(result_string)
}

#[tokio::main]
async fn main() {
    let check_connection = warp::path::end()
        .and_then(check_google_connection);

    warp::serve(check_connection).run(([0, 0, 0, 0], 3030)).await;
}