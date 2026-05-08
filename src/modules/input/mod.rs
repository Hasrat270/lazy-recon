pub mod reflected;
pub mod search;
pub mod forms;
pub mod idor;
pub mod mass_assignment;
pub mod parameter_pollution;
pub mod unicode_normalization;

use colored::*;

/// Run all User Input modules (30 total checks across categories)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{}", "═══════════════════════════════════════════════════".blue());
    println!("{} USER INPUT METHODOLOGY (30 Modules)", "▶▶▶".blue().bold());
    println!("{}", "═══════════════════════════════════════════════════".blue());

    // Sub-Category 1: Reflected Values (14 modules)
    reflected::run(target).await?;

    // Sub-Category 2: Search Functionalities (6 modules)
    search::run(target).await?;

    // Sub-Category 3: Forms, WebSockets & PostMsgs (4 modules)
    forms::run(target).await?;

    // Sub-Category 4: Logic & Discovery (6 modules)
    idor::detect(target).await?;
    mass_assignment::detect(target).await?;
    parameter_pollution::detect(target).await?;
    unicode_normalization::detect(target).await?;

    println!("\n{} User Input scan complete.", "[✓]".green());
    Ok(())
}
