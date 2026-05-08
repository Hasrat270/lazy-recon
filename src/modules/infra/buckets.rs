use colored::*;
use crate::core::client::HttpClient;

/// Storage Bucket exposure detection (S3, GCP, Azure, Firebase)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Storage Buckets & Firebase", "[*]".yellow());

    let client = HttpClient::new()?;
    
    // Extract bucket names from body (regex-like logic)
    let body = match client.inner.get(target).send().await {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => return Ok(()),
    };
    
    // Common patterns for buckets
    let patterns = vec![
        ".s3.amazonaws.com",
        "storage.googleapis.com",
        "core.windows.net",
        "firebaseio.com"
    ];
    
    for pattern in patterns {
        if body.contains(pattern) {
            println!("{} FOUND: Potential cloud storage usage ({})", "[!]".yellow(), pattern);
            // Further automation would involve trying to list/upload to these buckets
        }
    }

    Ok(())
}
