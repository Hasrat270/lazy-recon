use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// CSRF detection — missing anti-CSRF tokens and SameSite cookies
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Cross-Site Request Forgery (CSRF)", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    let body_lower = result.response_body.to_lowercase();

    // Check for forms without CSRF tokens
    let has_form = body_lower.contains("<form");
    let has_csrf_token = body_lower.contains("csrf")
        || body_lower.contains("_token")
        || body_lower.contains("authenticity_token")
        || body_lower.contains("__requestverificationtoken")
        || body_lower.contains("antiforgery");

    if has_form && !has_csrf_token {
        println!(
            "{} POTENTIAL: CSRF — Forms found without anti-CSRF tokens",
            "[!]".red().bold()
        );
        println!("    Impact: State-changing actions may be forgeable cross-origin");
    }

    // Check SameSite cookie attribute
    if let Some(set_cookie) = result.response_headers.get("set-cookie") {
        let cookie_lower = set_cookie.to_lowercase();
        if !cookie_lower.contains("samesite=strict") && !cookie_lower.contains("samesite=lax") {
            println!(
                "{} POTENTIAL: CSRF — Session cookie missing SameSite attribute",
                "[!]".red().bold()
            );
            println!("    Cookie: {}", set_cookie);
        }
        if cookie_lower.contains("samesite=none") && !cookie_lower.contains("secure") {
            println!(
                "{} FOUND: SameSite=None without Secure flag",
                "[!]".red().bold()
            );
        }
    }

    Ok(())
}
