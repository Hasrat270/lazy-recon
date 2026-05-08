use colored::*;
use crate::core::client::HttpClient;

/// Spring Actuator endpoint detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Spring Actuators", "[*]".yellow());

    let client = HttpClient::new()?;
    let endpoints = vec![
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/actuator/heapdump", "/actuator/trace", "/actuator/mappings",
        "/env", "/heapdump", "/trace", "/mappings"
    ];

    for ep in endpoints {
        let url = format!("{}{}", target.trim_end_matches('/'), ep);
        if let Ok(resp) = client.inner.get(&url).send().await {
            if resp.status().is_success() {
                let ct = resp.headers().get("content-type").map(|h| h.to_str().unwrap_or("")).unwrap_or("");
                if ct.contains("json") || ep.contains("heapdump") {
                    println!("{} FOUND: Sensitive Spring Actuator endpoint at {}", "[!]".red().bold(), url);
                    if ep.contains("heapdump") {
                        println!("    Impact: Full memory dump leakage (credentials, keys)");
                    } else if ep.contains("env") {
                        println!("    Impact: Environment variable leakage (API keys, secrets)");
                    }
                }
            }
        }
    }

    Ok(())
}
