use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Phone Number Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Phone Number Injections", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    // Phone number injection payloads
    let payloads = vec![
        ("+1234567890;ext=1", "Extension injection"),
        ("+1234567890%0d%0a", "CRLF in phone field"),
        ("tel:+1234567890", "URI scheme injection"),
        ("+{{7*7}}", "SSTI via phone field"),
        ("+1234567890' OR '1'='1", "SQLi via phone field"),
        ("+1234567890<script>alert(1)</script>", "XSS via phone field"),
    ];

    // Look for phone-related params
    let phone_params: Vec<&(String, String)> = params.iter()
        .filter(|(k, _)| {
            let k_lower = k.to_lowercase();
            k_lower.contains("phone") || k_lower.contains("tel")
                || k_lower.contains("mobile") || k_lower.contains("sms")
                || k_lower.contains("cell") || k_lower.contains("number")
        })
        .collect();

    let target_params: Vec<&(String, String)> = if phone_params.is_empty() {
        params.iter().collect()
    } else {
        phone_params
    };

    for (param_name, _) in target_params {
        for (payload, desc) in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                if result.status_code == 200 || result.status_code == 302 {
                    if result.response_body.contains("alert(1)")
                        || result.response_body.contains("49")
                        || result.response_body.contains("sql")
                    {
                        println!(
                            "{} POTENTIAL: Phone Number Injection in param '{}' — {}",
                            "[!]".red().bold(), param_name, desc
                        );
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}
