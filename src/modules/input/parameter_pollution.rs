use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// HTTP Parameter Pollution detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: HTTP Parameter Pollution (HPP)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    let baseline = Analyzer::send_and_analyze(&client, target, "").await?;

    for (param_name, original_val) in &params {
        // Inject duplicate parameter with different value
        let hpp_val = format!("lzrpollution_{}", rand::random::<u16>());
        let test_url = format!("{}&{}={}", target, param_name, hpp_val);
        
        if let Ok(result) = Analyzer::send_and_analyze(&client, &test_url, &hpp_val).await {
            if result.reflected_in_body {
                println!(
                    "{} FOUND: HTTP Parameter Pollution in param '{}'",
                    "[!]".yellow(), param_name
                );
                println!("    Reflection of second parameter value ('{}') detected", hpp_val);
                println!("    Impact: Can be used to bypass WAFs or manipulate backend logic");
            }
        }
    }

    Ok(())
}
