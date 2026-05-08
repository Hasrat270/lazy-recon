use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// XSSI — Cross-Site Script Inclusion detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Cross-Site Script Inclusion (XSSI)", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;

    // Check if endpoint returns sensitive JSON/JS that could be included cross-origin
    let content_type = result.response_headers.get("content-type")
        .map(|v| v.to_lowercase())
        .unwrap_or_default();

    let body = &result.response_body;

    // Check for JSON arrays (directly includable as JS)
    let vulnerable_patterns = vec![
        (body.starts_with("["), "JSON array response — directly executable as JS"),
        (body.starts_with("for(;;);"), "JSON hijacking protection present (safe)"),
        (body.starts_with(")]}'\n"), "Angular JSON protection present (safe)"),
        (body.contains("callback(") && content_type.contains("javascript"), "JSONP endpoint detected"),
    ];

    for (condition, desc) in &vulnerable_patterns {
        if *condition {
            if desc.contains("safe") || desc.contains("protection") {
                println!("{} {}", "[i]".cyan(), desc);
            } else {
                println!(
                    "{} POTENTIAL: XSSI — {}",
                    "[!]".red().bold(), desc
                );
                println!("    Impact: Sensitive data leakable via cross-origin script inclusion");
            }
        }
    }

    // Check for sensitive data in JS/JSON responses without XSSI protection
    let sensitive_keywords = ["email", "password", "token", "api_key", "secret", "ssn", "credit_card"];
    if (content_type.contains("json") || content_type.contains("javascript"))
        && !body.starts_with(")]}'\n")
        && !body.starts_with("for(;;);")
    {
        for keyword in &sensitive_keywords {
            if body.to_lowercase().contains(keyword) {
                println!(
                    "{} POTENTIAL: XSSI — Sensitive data ('{}') in unprotected JSON/JS response",
                    "[!]".red().bold(), keyword
                );
                break;
            }
        }
    }

    Ok(())
}
