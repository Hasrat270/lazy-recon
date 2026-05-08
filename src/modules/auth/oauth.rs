use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// OAuth vulnerability detection (redirect_uri, state, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: OAuth Vulnerabilities", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    
    // Check for OAuth endpoints in the page
    let oauth_patterns = vec!["client_id=", "redirect_uri=", "response_type=", "scope=", "state="];
    let body = &result.response_body;
    
    if oauth_patterns.iter().any(|p| body.contains(p)) {
        println!("{} FOUND: OAuth parameter usage detected in page", "[!]".yellow());
        
        // 1. Test redirect_uri manipulation
        let evil_redirect = "https://evil.lzrecon.com";
        let params = Analyzer::extract_params(target);
        for (param_name, _) in params {
            if param_name == "redirect_uri" {
                let url = Analyzer::inject_param(target, &param_name, evil_redirect)?;
                let resp = client.inner.get(&url).send().await?;
                
                if let Some(loc) = resp.headers().get("location") {
                    if loc.to_str().unwrap_or("").contains(evil_redirect) {
                        println!("{} CONFIRMED: OAuth Redirect URI Manipulation!", "[!]".red().bold());
                        println!("    Impact: Authorization code/token stealing via redirected URI");
                    }
                }
            }
        }
        
        // 2. Check for missing 'state' parameter (CSRF risk)
        if !body.contains("state=") {
            println!("{} POTENTIAL: OAuth implementation missing 'state' parameter (CSRF risk)", "[!]".yellow());
        }
    }

    Ok(())
}
