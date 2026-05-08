pub mod upload;
pub mod formula;
pub mod pdf;

use colored::*;

/// Run all File-related modules (3 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Files Methodology (3 Modules) ---", ":::".blue());

    // 1. File Upload
    upload::detect(target).await?;
    
    // 2. Formula Injection
    formula::detect(target).await?;
    
    // 3. PDF Injection
    pdf::detect(target).await?;

    Ok(())
}
