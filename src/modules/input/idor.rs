use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// IDOR (Insecure Direct Object Reference) detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: IDOR (Insecure Direct Object Reference)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let baseline = Analyzer::send_and_analyze(&client, target, "").await?;

    for (param_name, original_val) in &params {
        // Check if param looks like an ID (numeric or UUID)
        let is_numeric = original_val.chars().all(|c| c.is_digit(10));
        let is_uuid = original_val.len() == 36 && original_val.contains('-');

        if is_numeric || is_uuid {
            println!("{} Parameter '{}' looks like an ID — testing for IDOR", "[i]".cyan(), param_name);
            
            // Test increment/decrement for numeric IDs
            if is_numeric {
                if let Ok(id) = original_val.parse::<i64>() {
                    let test_ids = vec![id + 1, id - 1, 1, 0, 100, 1000];
                    for test_id in test_ids {
                        let url = Analyzer::inject_param(target, param_name, &test_id.to_string())?;
                        let result = Analyzer::send_and_analyze(&client, &url, "").await?;
                        
                        if result.status_code == 200 && result.response_body.len() > 100 {
                            // If response is successful and different from baseline, it might be an IDOR
                            let len_diff = (result.response_body.len() as i64 - baseline.response_body.len() as i64).unsigned_abs();
                            if len_diff > 50 {
                                println!(
                                    "{} POTENTIAL: IDOR in param '{}' (ID changed from {} to {})",
                                    "[!]".yellow(), param_name, original_val, test_id
                                );
                                println!("    Response size diff: {} bytes", len_diff);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
