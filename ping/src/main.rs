use warp::{Filter, Rejection, Reply};
// Removed: use std::convert::Infallible; // This import was unused
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol}; // Added NameServerConfig and Protocol
use trust_dns_resolver::Resolver;
use std::net::SocketAddr; // Useful for type clarity if parsing separately

async fn resolve_and_connect() -> Result<impl Reply, Rejection> {
    // First, resolve google.com using Google's DNS server (8.8.8.8)

    // Define the name server configuration
    let google_dns_socket_addr: SocketAddr = "8.8.8.8:53".parse()
        .expect("Failed to parse Google DNS socket address");

    let name_server = NameServerConfig {
        socket_addr: google_dns_socket_addr,
        protocol: Protocol::Udp, // Standard DNS typically uses UDP on port 53
        tls_dns_name: None,       // No TLS for standard DNS
        trust_negative_responses: true, // A common default
    };

    // The node does not guarantee that the IP for the dns.google network will be 8.8.8.8,
    // but for now, it is estimated to be so. The correct approach would be to check the configuration file.
    let resolver = Resolver::new(
        ResolverConfig::from_parts(None, vec![name_server], ResolverOpts::default()),
        ResolverOpts::default(),
    )
    .expect("Failed to create DNS resolver");

    // Resolve google.com to get its IP address
    let response_message = match resolver.lookup_ip("google.com") {
        Ok(lookup) => {
            if let Some(ip) = lookup.iter().next() {
                // Now make an HTTP request to the resolved IP
                let client = reqwest::Client::new();
                
                // When connecting to an IP directly in an HTTPS context, we need to specify the Host header
                match client
                    .get(format!("https://{}", ip))
                    .header("Host", "google.com") // Required for SNI (Server Name Indication)
                    .send()
                    .await
                {
                    Ok(response) => {
                        format!(
                            "Successfully resolved google.com to {} and connected via HTTPS. Status: {}",
                            ip, response.status()
                        )
                    }
                    Err(e) => format!("DNS resolution succeeded (IP: {}), but HTTPS request failed: {}", ip, e),
                }
            } else {
                "DNS resolution succeeded, but no IP addresses were returned".to_string()
            }
        }
        Err(e) => format!("DNS resolution failed: {}", e),
    };

    Ok(response_message)
}

#[tokio::main]
async fn main() {
    // Define the warp route at "/"
    let check_connection = warp::path::end().and_then(resolve_and_connect);

    println!("Server started at http://localhost:3030");
    
    // Start the server on port 3030
    warp::serve(check_connection).run(([0, 0, 0, 0], 3030)).await;
}