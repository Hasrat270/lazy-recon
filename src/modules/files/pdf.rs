use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// PDF Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: PDF Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    
    // PDF injection payloads (XSS in PDF)
    let payloads = vec![
        "<script>alert(1)</script>",
        "<b>lzrecon</b>",
        "<iframe src='http://169.254.169.254/latest/meta-data/'>",
    ];

    for (param_name, _) in &params {
        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let resp = client.inner.get(&url).send().await?;
            
            if let Some(ct) = resp.headers().get("content-type") {
                if ct.to_str().unwrap_or("").contains("application/pdf") {
                    println!(
                        "{} FOUND: PDF Generator detected at param '{}' — Check for injection!",
                        "[!]".yellow(), param_name
                    );
                }
            }
        }
    }

    Ok(())
}
