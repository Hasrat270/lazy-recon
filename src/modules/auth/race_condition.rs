use colored::*;
use crate::core::client::HttpClient;
use std::sync::Arc;
use tokio::task;

/// Race Condition detection via concurrent requests
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: Race Condition (Basic Concurrent Test)", "[*]".yellow());

    let client = Arc::new(HttpClient::new()?);
    let target_url = target.to_string();
    
    let mut handles = vec![];
    
    // Send 10 concurrent requests to see if we get inconsistent responses
    for i in 0..10 {
        let client_clone = Arc::clone(&client);
        let url = target_url.clone();
        
        handles.push(task::spawn(async move {
            let start = std::time::Instant::now();
            let resp = client_clone.inner.get(&url).send().await;
            (i, resp, start.elapsed())
        }));
    }
    
    let mut success_count = 0;
    for handle in handles {
        if let Ok((_, Ok(resp), _)) = handle.await {
            if resp.status().is_success() {
                success_count += 1;
            }
        }
    }
    
    println!("{} Completed 10 concurrent requests ({} successful)", "[i]".cyan(), success_count);
    println!("    Note: Real race conditions usually require authenticated state-changing actions.");

    Ok(())
}
