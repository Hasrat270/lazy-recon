use colored::*;
use crate::core::client::HttpClient;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Server Side Inclusion/Edge Side Inclusion", "[*]".yellow());
    
    let client = HttpClient::new()?;
    
    let payloads = vec![
        ("SSI Math", "<!--#element-7*7-->"),
        ("SSI Exec", "<!--#exec cmd=\"echo 49\" -->"),
        ("ESI Include", "<esi:include src=\"http://example.com/\" />"),
    ];

    for (name, payload) in payloads {
        let response = client.inner.get(target)
            .header("User-Agent", payload)
            .header("Referer", payload)
            .send()
            .await?;

        let body = response.text().await?;

        if body.contains("49") && !payload.contains("49") {
            println!("{} VULNERABLE: SSI Injection confirmed!", "[!]".red().bold());
        }
    }

    Ok(())
}
