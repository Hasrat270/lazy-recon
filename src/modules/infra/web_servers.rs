use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Web Server misconfiguration detection (Apache, Nginx, IIS)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Web Server Misconfigurations", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    
    // 1. Detect Server Header
    if let Some(server) = result.response_headers.get("server") {
        println!("{} Server Header: {}", "[i]".cyan(), server);
        
        if server.contains('/') {
            println!("{} POTENTIAL: Server version disclosure in header", "[!]".yellow());
        }
    }
    
    // 2. Test for PUT method (Arbitrary File Upload)
    if let Ok(resp) = client.inner.request(reqwest::Method::PUT, format!("{}/lzr_test.txt", target.trim_end_matches('/')))
        .body("lzr_test")
        .send().await
    {
        if resp.status().is_success() {
            println!("{} CRITICAL: PUT method enabled — Arbitrary file upload possible!", "[!]".red().bold());
        }
    }
    
    // 3. Test for directory listing
    let dirs = vec!["/images/", "/uploads/", "/css/", "/js/", "/backup/", "/config/"];
    for dir in dirs {
        let dir_url = format!("{}{}", target.trim_end_matches('/'), dir);
        if let Ok(resp) = client.inner.get(&dir_url).send().await {
            let body = resp.text().await?;
            if body.contains("Index of /") || body.contains("Directory Listing") {
                println!("{} FOUND: Directory Listing enabled at {}", "[!]".red(), dir_url);
            }
        }
    }

    Ok(())
}
