pub mod csrf;
pub mod cswsh;
pub mod postmessage;
pub mod phone_injection;

use colored::*;

/// Run all Forms/WebSockets/PostMessage modules (4 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Forms, WebSockets & PostMsgs (4 Modules) ---", ":::".blue());

    // 1. CSRF
    csrf::detect(target).await?;
    // 2. Cross-Site WebSocket Hijacking
    cswsh::detect(target).await?;
    // 3. PostMessage Vulnerabilities
    postmessage::detect(target).await?;
    // 4. Phone Number Injections
    phone_injection::detect(target).await?;

    Ok(())
}
