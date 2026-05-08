use colored::*;
use crate::core::client::HttpClient;
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
            let second_resp = client.inner.get(target).send().await?;
            let second_body = second_resp.text().await?;

            if second_body.contains(&canary) {
                println!("{} CONFIRMED: Cache Poisoning via {}!", "[!]".red().bold(), header_name);
            }
        }
    }

    Ok(())
}
