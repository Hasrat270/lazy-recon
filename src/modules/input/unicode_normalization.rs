use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Unicode Normalization vulnerability detection
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Unicode Normalization", "[*]".yellow());

    let params = Analyzer::extract_params(target);
    if params.is_empty() { return Ok(()); }

    let client = HttpClient::new()?;

    // Unicode characters that normalize to ASCII
    // ℀ (U+2100) -> a/c, ℁ (U+2101) -> a/s, etc.
    // ⓐ (U+24D0) -> a
    let test_chars = vec![
        ("\u{24D0}", "a", "Circled Latin Small Letter A"),
        ("\u{212A}", "k", "Kelvin Sign"),
        ("\u{FB01}", "fi", "Latin Small Ligature FI"),
    ];

    for (param_name, _) in &params {
        for (unicode, ascii, desc) in &test_chars {
            let url = Analyzer::inject_param(target, param_name, unicode)?;
            if let Ok(result) = Analyzer::send_and_analyze(&client, &url, ascii).await {
                if result.reflected_in_body && !result.response_body.contains(unicode) {
                    println!(
                        "{} POTENTIAL: Unicode Normalization vulnerability in param '{}'",
                        "[!]".yellow(), param_name
                    );
                    println!("    Character {} normalized to '{}' ({})", unicode, ascii, desc);
                    println!("    Impact: Can be used for account takeover (e.g., admin vs admın)");
                }
            }
        }
    }

    Ok(())
}
