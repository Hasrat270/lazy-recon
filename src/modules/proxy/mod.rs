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
    
    // 1. Abusing hop-by-hop headers
    hop_by_hop::detect(target).await?;
    
    // 2. Cache Poisoning/Cache Deception
    cache_poisoning::detect(target).await?;
    
    // 3. HTTP Connection Contamination
    connection_contamination::detect(target).await?;

    // 4. HTTP Connection Request Smuggling
    connection_request_smuggling::detect(target).await?;
    
    // 5. HTTP Request Smuggling
    request_smuggling::detect(target).await?;

    // 6. HTTP Response Smuggling / Desync
    response_smuggling::detect(target).await?;

    // 7. H2C Smuggling
    h2c_smuggling::detect(target).await?;

    // 8. SSI/ESI
    ssi_esi::detect(target).await?;

    // 9. Uncovering Cloudflare
    uncovering_cloudflare::detect(target).await?;

    // 10. XSLT Injection
    xslt_injection::detect(target).await?;

    // 11. Proxy / WAF Protections Bypass
    waf_bypass::detect(target).await?;
    
    Ok(())
}
