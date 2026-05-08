pub mod reflected;
pub mod search;
pub mod forms;

use colored::*;

/// Run all User Input modules (24 total checks across 3 sub-categories)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{}", "═══════════════════════════════════════════════════".blue());
    println!("{} USER INPUT METHODOLOGY (24 Modules)", "▶▶▶".blue().bold());
    println!("{}", "═══════════════════════════════════════════════════".blue());

    // Sub-Category 1: Reflected Values (14 modules)
    reflected::run(target).await?;

    // Sub-Category 2: Search Functionalities (6 modules)
    search::run(target).await?;

    // Sub-Category 3: Forms, WebSockets & PostMsgs (4 modules)
    forms::run(target).await?;

    println!("\n{} User Input scan complete.", "[✓]".green());
    Ok(())
}
