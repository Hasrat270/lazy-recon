use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Cross-Site WebSocket Hijacking detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Cross-Site WebSocket Hijacking (CSWSH)", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;

    // Check for WebSocket endpoints in the page source
    let ws_patterns = vec![
        "new WebSocket(",
        "new WebSocket (",
        "ws://",
        "wss://",
        ".onmessage",
        "socket.io",
    ];

    let body = &result.response_body;
    let mut ws_found = false;

    for pattern in &ws_patterns {
        if body.contains(pattern) {
            ws_found = true;
            println!("{} WebSocket usage detected: {}", "[i]".cyan(), pattern);
        }
    }

    if ws_found {
        // Check if WebSocket upgrade request validates Origin
        let ws_url = if target.starts_with("https") {
            target.replace("https://", "wss://")
        } else {
            target.replace("http://", "ws://")
        };

        // Try HTTP upgrade with spoofed Origin
        if let Ok(resp) = client.inner.get(target)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Origin", "https://evil.lzrecon.com")
            .send().await
        {
            let status = resp.status().as_u16();
            if status == 101 {
                println!(
                    "{} CONFIRMED: CSWSH — WebSocket accepts cross-origin upgrade!",
                    "[!]".red().bold()
                );
                println!("    Impact: Attacker page can hijack WebSocket session");
                return Ok(());
            }
            // Some servers return 200 with upgrade info
            if status == 200 {
                let body = resp.text().await?;
                if body.to_lowercase().contains("upgrade") {
                    println!(
                        "{} POTENTIAL: CSWSH — WebSocket endpoint may accept cross-origin",
                        "[!]".red().bold()
                    );
                }
            }
        }
    }

    Ok(())
}
