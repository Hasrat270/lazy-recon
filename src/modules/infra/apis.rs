use colored::*;
use crate::core::client::HttpClient;

/// Web API vulnerability detection (Swagger, Postman, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Web API Pentesting (Endpoints discovery)", "[*]".yellow());

    let client = HttpClient::new()?;
    let endpoints = vec![
        "/swagger-ui.html", "/swagger/index.html", "/v2/api-docs",
        "/v3/api-docs", "/swagger.json", "/api-docs", "/api/v1",
        "/api/v2", "/docs", "/redoc", "/postman"
    ];

    for ep in endpoints {
        let url = format!("{}{}", target.trim_end_matches('/'), ep);
        if let Ok(resp) = client.inner.get(&url).send().await {
            if resp.status().is_success() {
                println!("{} FOUND: API Documentation/Endpoint at {}", "[!]".yellow(), url);
            }
        }
    }

    Ok(())
}
