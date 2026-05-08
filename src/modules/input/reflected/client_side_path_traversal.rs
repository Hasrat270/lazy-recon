use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Client-Side Path Traversal detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Client Side Path Traversal", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    for (param_name, _) in &params {
        // Check if the parameter value is used in client-side fetch/XHR URLs
        let canary = format!("lzrcspt{}", rand::random::<u16>());
        let url = Analyzer::inject_param(target, param_name, &canary)?;
        if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
            let body = &result.response_body;

            // Check if param value appears in fetch/XHR/src URLs in the response
            let patterns = vec![
                format!("fetch(\"/{}", canary),
                format!("fetch('/{}", canary),
                format!("src=\"/{}", canary),
                format!("src='/{}", canary),
                format!("href=\"/{}", canary),
                format!("ajax({{url:\"/{}", canary),
                format!(".load(\"/{}", canary),
            ];

            for pattern in &patterns {
                if body.contains(pattern.as_str()) {
                    // Now test with traversal payload
                    let traversal = format!("..%2f..%2fadmin");
                    let test_url = Analyzer::inject_param(target, param_name, &traversal)?;
                    if let Ok(test_result) = Analyzer::send_and_analyze(&client, &test_url, "").await {
                        if test_result.response_body.contains("..%2f..%2fadmin")
                            || test_result.response_body.contains("../../admin")
                        {
                            println!(
                                "{} CONFIRMED: Client-Side Path Traversal in param '{}'",
                                "[!]".red().bold(), param_name
                            );
                            println!("    Impact: Attacker can manipulate client-side API paths");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
