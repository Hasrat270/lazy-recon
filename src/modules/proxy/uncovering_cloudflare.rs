use colored::*;
use crate::core::client::HttpClient;
use std::net::ToSocketAddrs;
use url::Url;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Uncovering Cloudflare", "[*]".yellow());
    
    let url = Url::parse(target)?;
    let domain = url.host_str().unwrap_or("");
    
    if domain.is_empty() { return Ok(()); }

    let subdomains = vec!["direct", "origin", "dev", "stage", "backend", "mail", "ftp", "cpanel"];
    
    for sub in subdomains {
        let candidate = format!("{}.{}", sub, domain);
        if let Ok(addrs) = (candidate.as_str(), 80).to_socket_addrs() {
            for addr in addrs {
                let ip = addr.ip();
                if !is_cloudflare_ip(&ip.to_string()) {
                    println!("{} POTENTIAL ORIGIN FOUND: {} -> {}", "[!]".red().bold(), candidate, ip);
                }
            }
        }
    }

    Ok(())
}

fn is_cloudflare_ip(ip: &str) -> bool {
    ip.starts_with("103.") || ip.starts_with("104.") || ip.starts_with("108.") || ip.starts_with("172.64.")
}
