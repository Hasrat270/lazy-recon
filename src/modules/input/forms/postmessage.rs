use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// PostMessage Vulnerability detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: PostMessage Vulnerabilities", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    let body = &result.response_body;

    // Check for event listeners without origin validation
    let has_listener = body.contains("addEventListener(\"message\"")
        || body.contains("addEventListener('message'")
        || body.contains("onmessage");

    let has_origin_check = body.contains("event.origin")
        || body.contains("e.origin")
        || body.contains("msg.origin");

    let has_postmessage = body.contains("postMessage(")
        || body.contains(".postMessage(");

    let has_wildcard = body.contains("postMessage(") && body.contains("\"*\"");

    if has_listener && !has_origin_check {
        println!(
            "{} CONFIRMED: PostMessage listener WITHOUT origin validation!",
            "[!]".red().bold()
        );
        println!("    Impact: Cross-origin messages accepted from any origin — DOM XSS possible");
    }

    if has_wildcard {
        println!(
            "{} FOUND: postMessage with targetOrigin=\"*\" — data sent to any origin",
            "[!]".red().bold()
        );
    }

    if has_postmessage && !has_listener && !has_wildcard {
        println!("{} PostMessage API usage detected (review manually)", "[i]".cyan());
    }

    Ok(())
}
