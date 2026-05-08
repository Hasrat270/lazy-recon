use colored::*;
use crate::core::client::HttpClient;

/// CORS Misconfiguration detection (Wildcards, Null origin, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: CORS Misconfigurations & Bypass", "[*]".yellow());

    let client = HttpClient::new()?;
    let evil_origin = "https://evil.lzrecon.com";
    
    // 1. Test with wildcard origin
    let resp1 = client.inner.get(target)
        .header("Origin", "*")
        .send().await?;
    
    if let Some(allow_origin) = resp1.headers().get("access-control-allow-origin") {
        if allow_origin == "*" {
            println!("{} FOUND: CORS Wildcard allowed (*)", "[!]".red().bold());
        }
    }
    
    // 2. Test with arbitrary origin reflection
    let resp2 = client.inner.get(target)
        .header("Origin", evil_origin)
        .send().await?;
    
    if let Some(allow_origin) = resp2.headers().get("access-control-allow-origin") {
        if allow_origin == evil_origin {
            println!("{} CONFIRMED: CORS Arbitrary Origin Reflection!", "[!]".red().bold());
            println!("    Origin: {}", evil_origin);
            
            if let Some(allow_creds) = resp2.headers().get("access-control-allow-credentials") {
                if allow_creds == "true" {
                    println!("{} CRITICAL: CORS allows Credentials with reflected origin!", "[!]".red().bold());
                }
            }
        }
    }
    
    // 3. Test with null origin
    let resp3 = client.inner.get(target)
        .header("Origin", "null")
        .send().await?;
    
    if let Some(allow_origin) = resp3.headers().get("access-control-allow-origin") {
        if allow_origin == "null" {
            println!("{} FOUND: CORS Null Origin allowed", "[!]".red().bold());
        }
    }

    Ok(())
}
