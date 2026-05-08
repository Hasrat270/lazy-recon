use colored::*;
use crate::core::client::RawClient;
use url::Url;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: HTTP Response Smuggling / Desync", "[*]".yellow());
    
    let url = Url::parse(target)?;
    let host = url.host_str().unwrap_or("");
    
    let payload = format!(
        "GET / HTTP/1.1\r\n\
        Host: {}\r\n\
        X-Ignore: X\r\n\
        \r\n",
        host
    );

    if let Ok(resp) = RawClient::send_raw(target, payload.as_bytes()).await {
        let status_lines: Vec<&str> = resp.lines().filter(|l| l.starts_with("HTTP/1.1")).collect();
        if status_lines.len() > 1 {
            println!("{} CONFIRMED: Response Smuggling detected!", "[!]".red().bold());
        }
    }

    Ok(())
}
