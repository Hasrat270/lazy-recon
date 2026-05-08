use colored::*;
use crate::core::client::HttpClient;

/// Framework detection (Django, Flask, Node, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Application Frameworks & Stacks", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = crate::core::analyzer::Analyzer::send_and_analyze(&client, target, "").await?;
    
    // Check headers and cookies for framework signatures
    let headers = &result.response_headers;
    
    if headers.contains_key("x-powered-by") {
        println!("{} Framework (via X-Powered-By): {}", "[i]".cyan(), headers.get("x-powered-by").unwrap());
    }
    
    if let Some(cookies) = headers.get("set-cookie") {
        if cookies.contains("sessionid") { println!("{} Potential Framework: Django", "[i]".cyan()); }
        if cookies.contains("PHPSESSID") { println!("{} Potential Framework: PHP", "[i]".cyan()); }
        if cookies.contains("connect.sid") { println!("{} Potential Framework: Express/NodeJS", "[i]".cyan()); }
        if cookies.contains(".AspNetCore") { println!("{} Potential Framework: ASP.NET Core", "[i]".cyan()); }
    }

    Ok(())
}
