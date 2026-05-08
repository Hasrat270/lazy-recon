use colored::*;
use crate::core::client::HttpClient;
use crate::core::reporter::Reporter;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Cache Poisoning/Cache Deception", "[*]".yellow());
    
    let client = HttpClient::new()?;
    
    let unkeyed_headers = vec![
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
    ];

    for header_name in unkeyed_headers {
        Reporter::progress(&format!("Probing unkeyed header: {}...", header_name));
        
        let canary = format!("lazy-recon-{}.com", rand::random::<u32>());
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str(header_name)?,
            HeaderValue::from_str(&canary)?
        );

        let response = client.inner.get(target)
            .headers(headers)
            .send()
            .await?;

        let body = response.text().await?;
        
        if body.contains(&canary) {
            Reporter::success(&format!("Reflection detected for header '{}'. Validating cache persistence...", header_name));
            
            // Try to fetch again without the header to see if it's cached
            let second_resp = client.inner.get(target).send().await?;
            let second_body = second_resp.text().await?;

            if second_body.contains(&canary) {
                Reporter::found("Cache Poisoning", &format!("Confirmed persistence via unkeyed header: {}", header_name));
            }
        }
    }

    Ok(())
}
