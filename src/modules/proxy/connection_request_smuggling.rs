use colored::*;
use crate::core::client::RawClient;
use url::Url;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: HTTP Connection Request Smuggling", "[*]".yellow());
    
    let url = Url::parse(target)?;
    let host = url.host_str().unwrap_or("");
    
    let payload = format!(
        "POST / HTTP/1.1\r\n\
        Host: {}\r\n\
        Connection: keep-alive\r\n\
        Proxy-Connection: keep-alive\r\n\
        Content-Length: 0\r\n\
        \r\n\
        GET /smuggled HTTP/1.1\r\n\
        Host: {}\r\n\
        \r\n",
        host, host
    );

    if let Ok(resp) = RawClient::send_raw(target, payload.as_bytes()).await {
        if resp.contains("HTTP/1.1 404") {
            println!("{} Potential Connection Request Smuggling detected!", "[!]".red().bold());
        }
    }

    Ok(())
}
