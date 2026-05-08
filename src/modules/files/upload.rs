use colored::*;
use crate::core::client::HttpClient;
use reqwest::multipart;

/// File Upload vulnerability detection (RCE, bypasses, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: File Upload Vulnerabilities", "[*]".yellow());

    let client = HttpClient::new()?;
    
    // Test payloads for upload bypass
    let payloads = vec![
        ("shell.php", "<?php echo 'lzrecon'; ?>", "image/jpeg"),
        ("shell.php.jpg", "<?php echo 'lzrecon'; ?>", "image/jpeg"),
        ("shell.phtml", "<?php echo 'lzrecon'; ?>", "application/x-httpd-php"),
        (".htaccess", "AddType application/x-httpd-php .lzr", "text/plain"),
    ];

    for (filename, content, mime) in payloads {
        let part = multipart::Part::bytes(content.as_bytes())
            .file_name(filename)
            .mime_str(mime)?;
            
        let form = multipart::Form::new().part("file", part);
        
        if let Ok(resp) = client.inner.post(target)
            .multipart(form)
            .send().await
        {
            if resp.status().is_success() {
                let body = resp.text().await?;
                if body.contains("success") || body.contains(filename) {
                    println!("{} POTENTIAL: File Upload Bypass — Uploaded '{}' successfully", "[!]".yellow(), filename);
                }
            }
        }
    }

    Ok(())
}
