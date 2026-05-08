use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Client-Side Template Injection (AngularJS, Vue.js, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Client Side Template Injection (CSTI)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    // (payload, expected_in_response, framework)
    let csti_probes: Vec<(&str, &str, &str)> = vec![
        ("{{7*7}}", "49", "AngularJS/Vue"),
        ("${7*7}", "49", "JS Template Literal"),
        ("{{constructor.constructor('return 1')()}}", "1", "AngularJS sandbox escape"),
        ("{{[].constructor.constructor('return 1')()}}", "1", "AngularJS sandbox escape v2"),
        ("[${7*7}]", "[49]", "Vue.js"),
    ];

    for (param_name, _) in &params {
        for (payload, expected, framework) in &csti_probes {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, expected).await {
                if result.reflected_in_body && !result.response_body.contains(payload) {
                    println!(
                        "{} CONFIRMED: Client-Side Template Injection in param '{}' — {}",
                        "[!]".red().bold(), param_name, framework
                    );
                    println!("    Payload: {}", payload);
                    println!("    Evaluated to: {}", expected);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
