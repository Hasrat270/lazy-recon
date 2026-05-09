use colored::*;

pub mod hop_by_hop;
pub mod cache_poisoning;
pub mod connection_contamination;
pub mod connection_request_smuggling;
pub mod request_smuggling;
pub mod response_smuggling;
pub mod h2c_smuggling;
pub mod ssi_esi;
pub mod uncovering_cloudflare;
pub mod xslt_injection;
pub mod waf_bypass;

pub async fn run(target: &str) -> anyhow::Result<()> {
    println!("\n{} --- Proxy Methodology (11 Modules) ---", ":::".blue());
    
    use crate::core::reporter::Reporter;

    // 1. Abusing hop-by-hop headers
    Reporter::info("Testing Hop-by-Hop headers...");
    if let Err(e) = hop_by_hop::detect(target).await {
        println!("{} Error in Hop-by-Hop: {}", "[x]".red(), e);
    }
    
    // 2. Cache Poisoning/Cache Deception
    Reporter::info("Testing Cache Poisoning/Deception...");
    if let Err(e) = cache_poisoning::detect(target).await {
        println!("{} Error in Cache Poisoning: {}", "[x]".red(), e);
    }
    
    // 3. HTTP Connection Contamination
    Reporter::info("Testing Connection Contamination...");
    if let Err(e) = connection_contamination::detect(target).await {
        println!("{} Error in Connection Contamination: {}", "[x]".red(), e);
    }

    // 4. HTTP Connection Request Smuggling
    Reporter::info("Testing Connection Request Smuggling...");
    if let Err(e) = connection_request_smuggling::detect(target).await {
        println!("{} Error in Connection Request Smuggling: {}", "[x]".red(), e);
    }
    
    // 5. HTTP Request Smuggling
    Reporter::info("Testing HTTP Request Smuggling (CL.TE/TE.CL)...");
    if let Err(e) = request_smuggling::detect(target).await {
        println!("{} Error in Request Smuggling: {}", "[x]".red(), e);
    }

    // 6. HTTP Response Smuggling / Desync
    Reporter::info("Testing Response Smuggling/Desync...");
    if let Err(e) = response_smuggling::detect(target).await {
        println!("{} Error in Response Smuggling: {}", "[x]".red(), e);
    }

    // 7. H2C Smuggling
    Reporter::info("Testing H2C Smuggling...");
    if let Err(e) = h2c_smuggling::detect(target).await {
        println!("{} Error in H2C Smuggling: {}", "[x]".red(), e);
    }

    // 8. SSI/ESI
    Reporter::info("Testing SSI/ESI Injections...");
    if let Err(e) = ssi_esi::detect(target).await {
        println!("{} Error in SSI/ESI: {}", "[x]".red(), e);
    }

    // 9. Uncovering Cloudflare
    Reporter::info("Testing Cloudflare IP Uncovering...");
    if let Err(e) = uncovering_cloudflare::detect(target).await {
        println!("{} Error in Cloudflare module: {}", "[x]".red(), e);
    }

    // 10. XSLT Injection
    Reporter::info("Testing XSLT Server-Side Injection...");
    if let Err(e) = xslt_injection::detect(target).await {
        println!("{} Error in XSLT module: {}", "[x]".red(), e);
    }

    // 11. Proxy / WAF Protections Bypass
    Reporter::info("Testing Proxy/WAF Bypasses...");
    if let Err(e) = waf_bypass::detect(target).await {
        println!("{} Error in WAF Bypass: {}", "[x]".red(), e);
    }
    
    Ok(())
}
