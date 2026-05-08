use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// SAML vulnerability detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: SAML Attacks", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    let body = &result.response_body;
    
    // Check for SAML keywords
    let saml_patterns = vec!["SAMLRequest", "SAMLResponse", "RelayState", "Assertion"];
    if saml_patterns.iter().any(|p| body.contains(p)) {
        println!("{} FOUND: SAML usage detected in page", "[!]".yellow());
        
        // SAML is complex to automate without full XML parsing and signing, 
        // but we can check for common insecure defaults.
        if body.contains("Signature") && !body.contains("X509Certificate") {
            println!("{} POTENTIAL: SAML response might be missing certificate verification", "[!]".yellow());
        }
    }

    Ok(())
}
