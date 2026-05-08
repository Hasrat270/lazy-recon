pub mod jwt;
pub mod xxe;
pub mod deserialization;
pub mod graphql;

use colored::*;

/// Run all Structured Object modules (4 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Structured Objects Methodology (4 Modules) ---", ":::".blue());

    // 1. JWT
    jwt::detect(target).await?;
    
    // 2. XXE
    xxe::detect(target).await?;
    
    // 3. Deserialization
    deserialization::detect(target).await?;
    
    // 4. GraphQL
    graphql::detect(target).await?;

    Ok(())
}
