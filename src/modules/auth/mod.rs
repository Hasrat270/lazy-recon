pub mod rate_limit;
pub mod race_condition;
pub mod login_bypass;
pub mod otp_bypass;

use colored::*;

/// Run all Bypass/Auth modules (4 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Bypasses Methodology (4 Modules) ---", ":::".blue());

    // 1. Rate Limit Bypass
    rate_limit::detect(target).await?;
    
    // 2. Race Condition
    race_condition::detect(target).await?;
    
    // 3. Login Bypass
    login_bypass::detect(target).await?;
    
    // 4. OTP Bypass
    otp_bypass::detect(target).await?;

    Ok(())
}
