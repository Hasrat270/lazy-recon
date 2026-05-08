use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// CSP Bypass detection via weak directives and unsafe-inline
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Content Security Policy (CSP) Bypass", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    
    if let Some(csp) = result.response_headers.get("content-security-policy") {
        let csp_lower = csp.to_lowercase();
        
        let weak_directives = vec![
            ("'unsafe-inline'", "Allows execution of inline scripts (high risk)"),
            ("'unsafe-eval'", "Allows use of eval() and similar functions"),
            ("*", "Allows loading resources from any origin"),
            ("data:", "Allows use of data: URIs for resources"),
            ("http:", "Allows loading resources over insecure HTTP"),
        ];
        
        let mut found_weakness = false;
        
        for (weak, desc) in weak_directives {
            if csp_lower.contains(weak) {
                println!("{} Weak CSP directive: {} — {}", "[!]".red(), weak, desc);
                found_weakness = true;
            }
        }
        
        // Check for missing important directives
        if !csp_lower.contains("default-src") {
            println!("{} Missing default-src directive", "[!]".red());
            found_weakness = true;
        }
        
        if !found_weakness {
            println!("{} CSP seems reasonably strong", "[✓]".green());
        } else {
            println!("{} POTENTIAL: CSP Bypass possible due to weak configuration", "[!]".red().bold());
        }
    } else {
        println!("{} Missing Content-Security-Policy header", "[!]".red());
    }

    Ok(())
}
