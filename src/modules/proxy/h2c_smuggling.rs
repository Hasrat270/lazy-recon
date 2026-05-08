use colored::*;
use crate::core::client::HttpClient;
use reqwest::header::{HeaderMap, HeaderValue, CONNECTION, UPGRADE};

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} {} Testing for H2C Smuggling...", "[*]".yellow(), target);
    
    let client = HttpClient::new()?;
    
    // 1. Construct the H2C upgrade request
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade, HTTP2-Settings"));
    headers.insert(UPGRADE, HeaderValue::from_static("h2c"));
    headers.insert("HTTP2-Settings", HeaderValue::from_static("AAMAAABkAAQAAP__")); // Basic base64 encoded H2C settings

    let response = client.inner.get(target)
        .headers(headers)
        .send()
        .await?;

    // 2. Check for 101 Switching Protocols
    if response.status().as_u16() == 101 {
        println!("{} VULNERABLE: H2C Smuggling confirmed (101 Switching Protocols)!", "[!]".red().bold());
        println!("    {} The proxy allowed an upgrade to H2C.", "Info".cyan());
    } else {
        println!("  {} Server did not accept H2C upgrade.", "Info".cyan());
    }

    Ok(())
}
