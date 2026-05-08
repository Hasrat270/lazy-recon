pub mod xss;
pub mod ssti;
pub mod command_injection;
pub mod crlf;
pub mod ssrf;
pub mod path_traversal;
pub mod open_redirect;
pub mod dangling_markup;
pub mod reverse_tab_nabbing;
pub mod xssi;
pub mod prototype_pollution;
pub mod client_side_template;
pub mod client_side_path_traversal;
pub mod xs_search;

use colored::*;

/// Run all Reflected Values modules (14 checks)
pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Reflected Values (14 Modules) ---", ":::".blue());

    use crate::core::reporter::Reporter;
    
    // 1. XSS
    Reporter::info("Scanning for XSS...");
    xss::detect(target).await?;
    
    // 2. SSTI
    Reporter::info("Scanning for SSTI...");
    ssti::detect(target).await?;
    
    // 3. Command Injection
    Reporter::info("Scanning for Command Injection...");
    command_injection::detect(target).await?;
    
    // 4. CRLF
    Reporter::info("Scanning for CRLF...");
    crlf::detect(target).await?;
    
    // 5. SSRF
    Reporter::info("Scanning for SSRF...");
    ssrf::detect(target).await?;
    
    // 6. Path Traversal / File Inclusion
    Reporter::info("Scanning for Path Traversal/LFI...");
    path_traversal::detect(target).await?;
    
    // 7. Open Redirect
    Reporter::info("Scanning for Open Redirect...");
    open_redirect::detect(target).await?;
    
    // 8. Dangling Markup
    Reporter::info("Scanning for Dangling Markup...");
    dangling_markup::detect(target).await?;
    
    // 9. Reverse Tab Nabbing
    Reporter::info("Scanning for Reverse Tab Nabbing...");
    reverse_tab_nabbing::detect(target).await?;
    
    // 10. XSSI
    Reporter::info("Scanning for XSSI...");
    xssi::detect(target).await?;
    
    // 11. Prototype Pollution
    Reporter::info("Scanning for Prototype Pollution...");
    prototype_pollution::detect(target).await?;
    
    // 12. Client Side Template Injection
    Reporter::info("Scanning for Client-Side Template Injection...");
    client_side_template::detect(target).await?;
    
    // 13. Client Side Path Traversal
    Reporter::info("Scanning for Client-Side Path Traversal...");
    client_side_path_traversal::detect(target).await?;
    
    // 14. XS-Search
    Reporter::info("Scanning for XS-Search...");
    xs_search::detect(target).await?;

    // NOTE: SSI/ESI and XSLT are reused from proxy module — no duplicate needed

    Ok(())
}
