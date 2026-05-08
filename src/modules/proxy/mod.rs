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
    hop_by_hop::detect(target).await?;
    
    // 2. Cache Poisoning/Cache Deception
    Reporter::info("Testing Cache Poisoning/Deception...");
    cache_poisoning::detect(target).await?;
    
    // 3. HTTP Connection Contamination
    Reporter::info("Testing Connection Contamination...");
    connection_contamination::detect(target).await?;

    // 4. HTTP Connection Request Smuggling
    Reporter::info("Testing Connection Request Smuggling...");
    connection_request_smuggling::detect(target).await?;
    
    // 5. HTTP Request Smuggling
    Reporter::info("Testing HTTP Request Smuggling (CL.TE/TE.CL)...");
    request_smuggling::detect(target).await?;

    // 6. HTTP Response Smuggling / Desync
    Reporter::info("Testing Response Smuggling/Desync...");
    response_smuggling::detect(target).await?;

    // 7. H2C Smuggling
    Reporter::info("Testing H2C Smuggling...");
    h2c_smuggling::detect(target).await?;

    // 8. SSI/ESI
    Reporter::info("Testing SSI/ESI Injections...");
    ssi_esi::detect(target).await?;

    // 9. Uncovering Cloudflare
    Reporter::info("Testing Cloudflare IP Uncovering...");
    uncovering_cloudflare::detect(target).await?;

    // 10. XSLT Injection
    Reporter::info("Testing XSLT Server-Side Injection...");
    xslt_injection::detect(target).await?;

    // 11. Proxy / WAF Protections Bypass
    Reporter::info("Testing Proxy/WAF Bypasses...");
    waf_bypass::detect(target).await?;
    
    Ok(())
}
