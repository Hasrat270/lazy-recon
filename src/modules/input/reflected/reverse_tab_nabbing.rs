use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// Reverse Tab Nabbing — target="_blank" without rel="noopener"
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Reverse Tab Nabbing", "[*]".yellow());

    let client = HttpClient::new()?;
    let result = Analyzer::send_and_analyze(&client, target, "").await?;
    let body = result.response_body.to_lowercase();

    // Find links with target="_blank" missing rel="noopener noreferer"
    let mut pos = 0;
    while let Some(idx) = body[pos..].find("target=\"_blank\"") {
        let start = if idx > 200 { pos + idx - 200 } else { pos };
        let end = std::cmp::min(pos + idx + 50, body.len());
        let context = &body[start..end];

        if context.contains("<a ") && !context.contains("noopener") {
            println!(
                "{} FOUND: Reverse Tab Nabbing — <a target=\"_blank\"> without rel=\"noopener\"",
                "[!]".red().bold()
            );
            println!("    Impact: Opened page can hijack the opener via window.opener");
            return Ok(());
        }
        pos = pos + idx + 15;
    }

    Ok(())
}
