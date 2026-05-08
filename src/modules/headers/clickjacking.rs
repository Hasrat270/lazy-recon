use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Clickjacking detection via X-Frame-Options and Content-Security-Policy
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Clickjacking / Iframe Traps", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    
    let headers = &result.response_headers;
    
    let x_frame_options = headers.get("x-frame-options").map(|s| s.to_lowercase());
    let csp = headers.get("content-security-policy").map(|s| s.to_lowercase());
    
    let mut vulnerable = true;
    
    if let Some(xfo) = x_frame_options {
        if xfo == "deny" || xfo == "sameorigin" {
            vulnerable = false;
        } else {
            println!("{} Weak X-Frame-Options: {}", "[!]".red(), xfo);
        }
    }
    
    if let Some(csp_val) = csp {
        if csp_val.contains("frame-ancestors 'none'") || csp_val.contains("frame-ancestors 'self'") {
            vulnerable = false;
        } else if csp_val.contains("frame-ancestors") {
            println!("{} Weak CSP frame-ancestors detected", "[!]".red());
        }
    }
    
    if vulnerable {
        println!(
            "{} CONFIRMED: Clickjacking vulnerability — Missing X-Frame-Options and frame-ancestors",
            "[!]".red().bold()
        );
        println!("    Impact: Target can be embedded in an iframe on an attacker-controlled site");
    } else {
        println!("{} Clickjacking protection present", "[✓]".green());
    }

    Ok(())
}
