use colored::*;
use crate::core::client::HttpClient;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: XSLT Server Side Injection", "[*]".yellow());
    
    let client = HttpClient::new()?;
    
    let payloads = vec![
        ("XSLT Math", "<?xml version=\"1.0\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"7 * 7\"/></xsl:template></xsl:stylesheet>"),
        ("XSLT Version", "<?xml version=\"1.0\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"system-property('xsl:version')\"/></xsl:template></xsl:stylesheet>"),
    ];

    for (name, payload) in payloads {
        let response = client.inner.post(target)
            .header("Content-Type", "application/xml")
            .body(payload)
            .send()
            .await?;

        let body = response.text().await?;

        if body.contains("49") && !payload.contains("49") {
            println!("{} VULNERABLE: XSLT Injection confirmed!", "[!]".red().bold());
        }
    }

    Ok(())
}
