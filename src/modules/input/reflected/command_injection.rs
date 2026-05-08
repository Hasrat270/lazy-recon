use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Command Injection detection via time-based and echo-based methods
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Command Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for Command Injection testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;
    let canary = format!("lzrcmd{}", rand::random::<u32>());

    // Echo-based detection (fastest confirmation)
    let echo_payloads: Vec<String> = vec![
        format!(";echo {}", canary),
        format!("|echo {}", canary),
        format!("$(echo {})", canary),
        format!("`echo {}`", canary),
        format!("& echo {} &", canary),
    ];

    for (param_name, original_val) in &params {
        // Phase 1: Echo-based
        for payload in &echo_payloads {
            let full_payload = format!("{}{}", original_val, payload);
            let url = Analyzer::inject_param(target, param_name, &full_payload)?;
            let result = Analyzer::send_and_analyze(&client, &url, &canary).await?;

            if result.reflected_in_body {
                println!(
                    "{} CONFIRMED: Command Injection in param '{}' (echo-based)",
                    "[!]".red().bold(), param_name
                );
                println!("    Payload: {}", payload);
                return Ok(());
            }
        }

        // Phase 2: Time-based confirmation
        let time_payloads = vec![
            (format!("{};sleep 5", original_val), 5),
            (format!("{}|sleep 5", original_val), 5),
            (format!("{}$(sleep 5)", original_val), 5),
            (format!("{}`sleep 5`", original_val), 5),
            (format!("{}%0asleep 5", original_val), 5),
        ];

        // Get baseline timing
        let baseline = Analyzer::send_and_analyze(&client, target, "").await?;
        let baseline_ms = baseline.response_time_ms;

        for (payload, expected_delay) in &time_payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            let result = Analyzer::send_and_analyze(&client, &url, "").await?;

            let delay_threshold = (expected_delay * 1000) as u128;
            if result.response_time_ms > baseline_ms + delay_threshold - 500 {
                // Double-check with a different sleep value
                let verify_payload = format!("{};sleep 3", original_val);
                let verify_url = Analyzer::inject_param(target, param_name, &verify_payload)?;
                let verify_result = Analyzer::send_and_analyze(&client, &verify_url, "").await?;

                if verify_result.response_time_ms > baseline_ms + 2500 {
                    println!(
                        "{} CONFIRMED: Command Injection in param '{}' (time-based)",
                        "[!]".red().bold(), param_name
                    );
                    println!("    Payload: {}", payload);
                    println!("    Delay: {}ms (baseline: {}ms)", result.response_time_ms, baseline_ms);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
