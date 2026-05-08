use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Formula Injection detection (CSV/Excel)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Formula Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    
    // Formula injection payloads
    let payloads = vec![
        "=1+1",
        "=SUM(1,1)",
        "-1+1",
        "@SUM(1,1)",
        "+1+1",
    ];

    for (param_name, _) in &params {
        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let result = Analyzer::send_and_analyze(&client, &url, payload).await?;
            
            if result.reflected_in_body {
                println!(
                    "{} POTENTIAL: Formula Injection in param '{}' — Payload '{}' reflected",
                    "[!]".yellow(), param_name, payload
                );
            }
        }
    }

    Ok(())
}
