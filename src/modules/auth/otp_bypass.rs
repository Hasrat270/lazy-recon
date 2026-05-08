use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// OTP/2FA Bypass detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: 2FA/OTP Bypass", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;
    
    // Test common weak OTPs
    let weak_otps = vec!["0000", "1234", "000000", "123456", "9999"];
    
    for (param_name, _) in &params {
        if param_name.to_lowercase().contains("otp") || param_name.to_lowercase().contains("code") {
            for otp in &weak_otps {
                let url = Analyzer::inject_param(target, param_name, otp)?;
                let resp = client.inner.get(&url).send().await?;
                
                if resp.status().is_success() || resp.status().is_redirection() {
                    println!(
                        "{} POTENTIAL: Weak OTP accepted ('{}') in param '{}'",
                        "[!]".red().bold(), otp, param_name
                    );
                }
            }
        }
    }

    Ok(())
}
