use colored::*;
use crate::core::client::RawClient;
use url::Url;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: HTTP Connection Contamination", "[*]".yellow());
    
    let url = Url::parse(target)?;
    let host = url.host_str().unwrap_or("");
    
    let payload = format!(
        "POST / HTTP/1.1\r\n\
        Host: {}\r\n\
        Content-Length: 5\r\n\
        Connection: keep-alive\r\n\
        \r\n\
        0\r\n\
        \r\n\
        GET /lazy-recon-test HTTP/1.1\r\n\
        Host: {}\r\n\
        \r\n",
        host, host
    );

    if let Ok(response) = RawClient::send_raw(target, payload.as_bytes()).await {
        if response.contains("HTTP/1.1 404") || response.contains("/lazy-recon-test") {
            println!("{} Potential Connection Contamination detected!", "[!]".red().bold());
        }
    }

    Ok(())
}
