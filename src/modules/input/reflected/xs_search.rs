use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;
use std::time::Instant;

/// XS-Search / Cross-Site Search timing side-channel detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: XS-Search (Timing Side-Channel)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    for (param_name, _) in &params {
        // Send multiple requests with different search lengths and measure timing variance
        let mut timings: Vec<(String, u128)> = vec![];

        let test_values = vec!["a", "aaaaaaaaa", "z", "zzzzzzzzz", "1", "111111111"];

        for val in &test_values {
            let url = Analyzer::inject_param(target, param_name, val)?;
            let start = Instant::now();
            if let Ok(_) = client.inner.get(&url).send().await {
                let elapsed = start.elapsed().as_millis();
                timings.push((val.to_string(), elapsed));
            }
        }

        if timings.len() >= 4 {
            let times: Vec<u128> = timings.iter().map(|(_, t)| *t).collect();
            let min = *times.iter().min().unwrap();
            let max = *times.iter().max().unwrap();
            let variance = max - min;

            // Significant timing variance suggests search-dependent processing
            if variance > 500 {
                println!(
                    "{} POTENTIAL: XS-Search timing variance in param '{}' — {}ms spread",
                    "[!]".red().bold(), param_name, variance
                );
                println!("    Min: {}ms, Max: {}ms", min, max);
                println!("    Impact: Cross-origin information leakage via timing");
            }
        }
    }

    Ok(())
}
