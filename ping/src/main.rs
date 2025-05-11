use warp::{Filter, Rejection, Reply};
use std::convert::Infallible;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

async fn resolve_and_connect() -> Result<impl Reply, Rejection> {
    // First, resolve google.com using Google's DNS server (8.8.8.8)

    // The node does not guarantee that the IP for the dns.google network will be 8.8.8.8, but for now, it is estimated to be so. The correct approach would be to check the configuration file.
    let resolver = Resolver::new(
        ResolverConfig::from_parts(None, vec!["8.8.8.8:53".parse().unwrap()], Default::default()),
        ResolverOpts::default(),
    )
    .expect("Failed to create DNS resolver");

    // Resolve google.com to get its IP address
    let response = match resolver.lookup_ip("google.com") {
        Ok(lookup) => {
            if let Some(ip) = lookup.iter().next() {
                // Now make an HTTP request to the resolved IP
                let client = reqwest::Client::new();
                
                // When connecting to an IP directly in an HTTPS context, we need to specify the Host header
                match client
                    .get(format!("https://{}", ip))
                    .header("Host", "google.com") // Required for SNI
                    .send()
                    .await
                {
                    Ok(response) => {
                        format!(
                            "Successfully resolved google.com to {} and connected via HTTP. Status: {}",
                            ip, response.status()
                        )
                    }
                    Err(e) => format!("DNS resolution succeeded, but HTTP request failed: {}", e),
                }
            } else {
                "DNS resolution succeeded, but no IP addresses were returned".to_string()
            }
        }
        Err(e) => format!("DNS resolution failed: {}", e),
    };

    Ok(response)
}

#[tokio::main]
async fn main() {
    // Define the warp route at "/"
    let check_connection = warp::path::end().and_then(resolve_and_connect);

    println!("Server started at http://localhost:3030");
    
    // Start the server on port 3030
    warp::serve(check_connection).run(([0, 0, 0, 0], 3030)).await;
}