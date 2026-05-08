pub mod clickjacking;
pub mod csp;
pub mod cookies;
pub mod cors;

use colored::*;

/// Run all HTTP Header modules (4 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- HTTP Headers Methodology (4 Modules) ---", ":::".blue());

    // 1. Clickjacking
    clickjacking::detect(target).await?;
    
    // 2. CSP Bypass
    csp::detect(target).await?;
    
    // 3. Cookie Hacking
    cookies::detect(target).await?;
    
    // 4. CORS Misconfigurations
    cors::detect(target).await?;

    Ok(())
}
