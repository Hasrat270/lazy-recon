use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Cookie security auditing (HttpOnly, Secure, SameSite)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Cookie Security / Cookies Hacking", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    
    if let Some(set_cookie) = result.response_headers.get("set-cookie") {
        let cookies: Vec<&str> = set_cookie.split(',').collect();
        
        for cookie in cookies {
            let cookie_lower = cookie.to_lowercase();
            let mut issues = vec![];
            
            if !cookie_lower.contains("httponly") {
                issues.push("Missing HttpOnly (accessible via JS)");
            }
            
            if !cookie_lower.contains("secure") {
                issues.push("Missing Secure (transmitted over HTTP)");
            }
            
            if !cookie_lower.contains("samesite") {
                issues.push("Missing SameSite (CSRF risk)");
            } else if cookie_lower.contains("samesite=none") && !cookie_lower.contains("secure") {
                issues.push("SameSite=None without Secure flag");
            }
            
            if !issues.is_empty() {
                let cookie_name = cookie.split('=').next().unwrap_or("Unknown").trim();
                println!("{} Security issues with cookie '{}':", "[!]".red(), cookie_name);
                for issue in issues {
                    println!("    - {}", issue);
                }
            }
        }
    } else {
        println!("{} No cookies set by server", "[i]".cyan());
    }

    Ok(())
}
