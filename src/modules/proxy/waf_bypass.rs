use colored::*;
use crate::core::client::HttpClient;
use reqwest::header::{HeaderMap, HeaderValue, HeaderName};
use std::str::FromStr;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Proxy / WAF Protections Bypass", "[*]".yellow());
    
    let client = HttpClient::new()?;
    
    let spoof_headers = vec![
        "X-Forwarded-For",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "True-Client-IP",
        "X-Real-IP",
    ];

    for header in spoof_headers {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_str(header)?, HeaderValue::from_static("127.0.0.1"));
        
        let _ = client.inner.get(target)
            .headers(headers)
            .send()
            .await?;
    }

    Ok(())
}
