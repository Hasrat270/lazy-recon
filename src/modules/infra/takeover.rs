use colored::*;
use crate::core::client::HttpClient;

/// Domain and Subdomain Takeover detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Domain/Subdomain Takeover", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = crate::core::analyzer::Analyzer::send_and_analyze(&client, target, "").await?;
    let body = &result.response_body;
    
    // Signatures for common services prone to takeover
    let takeover_sigs = vec![
        ("NoSuchBucket", "Amazon S3"),
        ("NoSuchKey", "Amazon S3"),
        ("There is no app configured at this address", "Heroku"),
        ("404 Not Found", "GitHub Pages"),
        ("The specified bucket does not exist", "Amazon S3"),
        ("Repository not found", "GitHub"),
        ("The requested URL was not found on this server", "Google Cloud"),
        ("Project not found", "Firebase"),
    ];

    for (sig, service) in takeover_sigs {
        if body.contains(sig) {
            println!("{} POTENTIAL: Domain Takeover detected! Signature of {} found.", "[!]".red().bold(), service);
            println!("    Signature: '{}'", sig);
        }
    }

    Ok(())
}
