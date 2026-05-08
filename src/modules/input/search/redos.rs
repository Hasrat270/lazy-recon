use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// ReDoS — Regular Expression Denial of Service detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: ReDoS (Regex Denial of Service)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let baseline = Analyzer::send_and_analyze(&client, target, "").await?;

    // Evil regex payloads that exploit catastrophic backtracking
    let redos_payloads = vec![
        "a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]!".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaa\\".to_string(),
        "a]".repeat(25),
        "a".repeat(50),
    ];

    for (param_name, _) in &params {
        for payload in &redos_payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                // Significant delay compared to baseline suggests regex backtracking
                if result.response_time_ms > baseline.response_time_ms + 3000 {
                    println!(
                        "{} POTENTIAL: ReDoS in param '{}' — {}ms delay (baseline: {}ms)",
                        "[!]".red().bold(), param_name, result.response_time_ms, baseline.response_time_ms
                    );
                    println!("    Payload length: {} chars", payload.len());
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
