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
    if let Err(e) = xss::detect(target).await {
        println!("{} Error in XSS: {}", "[x]".red(), e);
    }
    
    // 2. SSTI
    Reporter::info("Scanning for SSTI...");
    if let Err(e) = ssti::detect(target).await {
        println!("{} Error in SSTI: {}", "[x]".red(), e);
    }
    
    // 3. Command Injection
    Reporter::info("Scanning for Command Injection...");
    if let Err(e) = command_injection::detect(target).await {
        println!("{} Error in Command Injection: {}", "[x]".red(), e);
    }
    
    // 4. CRLF
    Reporter::info("Scanning for CRLF...");
    if let Err(e) = crlf::detect(target).await {
        println!("{} Error in CRLF: {}", "[x]".red(), e);
    }
    
    // 5. SSRF
    Reporter::info("Scanning for SSRF...");
    if let Err(e) = ssrf::detect(target).await {
        println!("{} Error in SSRF: {}", "[x]".red(), e);
    }
    
    // 6. Path Traversal / File Inclusion
    Reporter::info("Scanning for Path Traversal/LFI...");
    if let Err(e) = path_traversal::detect(target).await {
        println!("{} Error in Path Traversal: {}", "[x]".red(), e);
    }
    
    // 7. Open Redirect
    Reporter::info("Scanning for Open Redirect...");
    if let Err(e) = open_redirect::detect(target).await {
        println!("{} Error in Open Redirect: {}", "[x]".red(), e);
    }
    
    // 8. Dangling Markup
    Reporter::info("Scanning for Dangling Markup...");
    if let Err(e) = dangling_markup::detect(target).await {
        println!("{} Error in Dangling Markup: {}", "[x]".red(), e);
    }
    
    // 9. Reverse Tab Nabbing
    Reporter::info("Scanning for Reverse Tab Nabbing...");
    if let Err(e) = reverse_tab_nabbing::detect(target).await {
        println!("{} Error in Tab Nabbing: {}", "[x]".red(), e);
    }
    
    // 10. XSSI
    Reporter::info("Scanning for XSSI...");
    if let Err(e) = xssi::detect(target).await {
        println!("{} Error in XSSI: {}", "[x]".red(), e);
    }
    
    // 11. Prototype Pollution
    Reporter::info("Scanning for Prototype Pollution...");
    if let Err(e) = prototype_pollution::detect(target).await {
        println!("{} Error in Prototype Pollution: {}", "[x]".red(), e);
    }
    
    // 12. Client Side Template Injection
    Reporter::info("Scanning for Client-Side Template Injection...");
    if let Err(e) = client_side_template::detect(target).await {
        println!("{} Error in CSTI: {}", "[x]".red(), e);
    }
    
    // 13. Client Side Path Traversal
    Reporter::info("Scanning for Client-Side Path Traversal...");
    if let Err(e) = client_side_path_traversal::detect(target).await {
        println!("{} Error in CSPT: {}", "[x]".red(), e);
    }
    
    // 14. XS-Search
    Reporter::info("Scanning for XS-Search...");
    if let Err(e) = xs_search::detect(target).await {
        println!("{} Error in XS-Search: {}", "[x]".red(), e);
    }

    // NOTE: SSI/ESI and XSLT are reused from proxy module — no duplicate needed

    Ok(())
}
