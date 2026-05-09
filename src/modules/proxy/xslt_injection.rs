use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;
use crate::core::reporter::Reporter;

pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: XSLT Server Side Injection", "[*]".yellow());
    
    let client = HttpClient::new()?;
    let params = Analyzer::extract_params(target);
    
    let payloads = vec![
        ("XSLT Version", "<?xml version=\"1.0\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"system-property('xsl:version')\"/></xsl:template></xsl:stylesheet>", "1.0"),
        ("XSLT Vendor", "<?xml version=\"1.0\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"system-property('xsl:vendor')\"/></xsl:template></xsl:stylesheet>", "Libxml2"),
    ];

    // Test in Parameters
    for (param_name, _) in params {
        for (name, payload, check) in &payloads {
            let url = Analyzer::inject_param(target, &param_name, payload)?;
            let resp = client.inner.get(&url).send().await?;
            
            if resp.text().await?.contains(check) {
                Reporter::found("XSLT Injection", &format!("Detected via {} in parameter '{}'", name, param_name), &format!("Target: {} | Parameter: {} | Payload: {}", target, param_name, payload));
            }
        }
    }

    Ok(())
}
