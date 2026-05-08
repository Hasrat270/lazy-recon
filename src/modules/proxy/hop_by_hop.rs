use colored::*;
use crate::core::client::HttpClient;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION};
use std::str::FromStr;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Abusing hop-by-hop headers", "[*]".yellow());
    
    let client = HttpClient::new()?;
    
    let baseline = client.inner.get(target).send().await?;
    let baseline_headers = baseline.headers().clone();
    
    let test_candidates = vec!["Server", "Date", "Content-Type", "X-Powered-By"];
    let mut found_vulnerable = false;

    for candidate in test_candidates {
        if baseline_headers.contains_key(candidate) {
            let mut headers = HeaderMap::new();
            let conn_value = format!("close, {}", candidate);
            headers.insert(CONNECTION, HeaderValue::from_str(&conn_value)?);
            
            let response = client.inner.get(target)
                .headers(headers)
                .send()
                .await?;
            
            if !response.headers().contains_key(candidate) {
                println!("{} Potential Hop-by-Hop Abuse! Proxy removed the '{}' header.", "[!]".red().bold(), candidate);
                found_vulnerable = true;
                break; 
            }
        }
    }

    Ok(())
}
