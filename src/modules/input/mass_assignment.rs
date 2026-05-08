use colored::*;
use crate::core::client::HttpClient;

/// Mass Assignment detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Mass Assignment", "[*]".yellow());

    let client = HttpClient::new()?;
    
    // Common sensitive fields to inject
    let sensitive_fields = vec![
        "admin", "is_admin", "role", "privilege", "superuser",
        "email", "account_status", "verified", "credits", "balance"
    ];

    for field in sensitive_fields {
        // Try injecting in JSON body for POST/PUT
        let json_payload = format!(r#"{{"{}": true}}"#, field);
        if let Ok(resp) = client.inner.post(target)
            .header("Content-Type", "application/json")
            .body(json_payload)
            .send().await
        {
            if resp.status().is_success() {
                println!("{} POTENTIAL: Mass Assignment via JSON field '{}'", "[!]".yellow(), field);
            }
        }
        
        // Try injecting as query parameter
        let url = if target.contains('?') {
            format!("{}&{}=true", target, field)
        } else {
            format!("{}?{}=true", target, field)
        };
        
        if let Ok(resp) = client.inner.get(&url).send().await {
            if resp.status().is_success() {
                // Check if reflection occurs
                let body = resp.text().await?;
                if body.contains(field) && body.contains("true") {
                    println!("{} POTENTIAL: Mass Assignment via query parameter '{}'", "[!]".yellow(), field);
                }
            }
        }
    }

    Ok(())
}
