pub mod web_servers;
pub mod spring_actuators;
pub mod buckets;
pub mod apis;
pub mod cms;
pub mod frameworks;
pub mod takeover;

use colored::*;

/// Run all Infrastructure & Middleware modules (7 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Infrastructure & Middleware Methodology (7 Modules) ---", ":::".blue());

    // 1. Web Servers
    web_servers::detect(target).await?;
    
    // 2. Spring Actuators
    spring_actuators::detect(target).await?;
    
    // 3. Cloud Buckets
    buckets::detect(target).await?;
    
    // 4. API Discovery
    apis::detect(target).await?;
    
    // 5. CMS (Placeholder)
    cms::detect(target).await?;
    
    // 6. Frameworks
    frameworks::detect(target).await?;
    
    // 7. Domain Takeover
    takeover::detect(target).await?;

    Ok(())
}
