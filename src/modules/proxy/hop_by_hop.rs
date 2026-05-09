use colored::*;
use crate::core::client::HttpClient;
use crate::core::reporter::Reporter;
use reqwest::header::{HeaderMap, HeaderValue, CONNECTION};

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Abusing hop-by-hop headers", "[*]".yellow());

    let client = HttpClient::new()?;
    Reporter::progress("Fetching baseline response to identify static headers...");
    
    let baseline = client.inner.get(target).send().await?;
    let baseline_headers = baseline.headers().clone();
    
    let test_candidates = vec!["Server", "Date", "Content-Type", "X-Powered-By"];
    let mut _found_vulnerable = false;

    for candidate in test_candidates {
        if baseline_headers.contains_key(candidate) {
            Reporter::progress(&format!("Attempting to remove '{}' using Connection header injection...", candidate));
            
            let mut headers = HeaderMap::new();
            let conn_value = format!("close, {}", candidate);
            headers.insert(CONNECTION, HeaderValue::from_str(&conn_value)?);
            
            let response = client.inner.get(target)
                .headers(headers)
                .send()
                .await?;
            
            if !response.headers().contains_key(candidate) {
                Reporter::found("Hop-by-Hop Abuse", &format!("Proxy stripped the '{}' header", candidate), &format!("Add 'Connection: {}, close' to your request and check if '{}' header disappears.", candidate, candidate));
                _found_vulnerable = true;
                break; 
            }
        }
    }

    Ok(())
}
