pub mod sqli;
pub mod nosqli;
pub mod ldap;
pub mod xpath;
pub mod orm_rsql;
pub mod redos;

use colored::*;

/// Run all Search Functionality modules (6 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Search Functionalities (6 Modules) ---", ":::".blue());

    // 1. SQL Injection
    sqli::detect(target).await?;
    // 2. NoSQL Injection
    nosqli::detect(target).await?;
    // 3. LDAP Injection
    ldap::detect(target).await?;
    // 4. XPath Injection
    xpath::detect(target).await?;
    // 5. ORM / RSQL Injection
    orm_rsql::detect(target).await?;
    // 6. ReDoS
    redos::detect(target).await?;

    // NOTE: File Inclusion shared with reflected/path_traversal module

    Ok(())
}
