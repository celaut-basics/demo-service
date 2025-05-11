use warp::{Filter, Rejection, Reply};
use reqwest::Client;
use std::convert::Infallible;
use std::process::Command;
use std::path::Path;

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
    let conf_dns_path = Path::new("src").join("conf_dns");

    if conf_dns_path.exists() {
        println!("Attempting to run {:?}", conf_dns_path);
        match Command::new(&conf_dns_path)
            .spawn() // Use spawn() to run the command in the background
        {
            Ok(_) => println!("Successfully started conf_dns in the background."),
            Err(e) => eprintln!("Failed to start conf_dns: {}", e),
        }
    } else {
        eprintln!("Executable not found at {:?}", conf_dns_path);
        eprintln!("Please ensure 'conf_dns' is compiled and located in the 'src' directory.");
    }

    let check_connection = warp::path::end()
        .and_then(check_google_connection);

    println!("Starting warp server on http://0.0.0.0:3030");
    warp::serve(check_connection).run(([0, 0, 0, 0], 3030)).await;
}
