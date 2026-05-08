use colored::*;
use crate::core::client::HttpClient;
use crate::core::analyzer::Analyzer;

/// GraphQL vulnerability detection (Introspection, Circular Queries, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: GraphQL Attacks", "[*]".yellow());

    let client = HttpClient::new()?;
    
    // 1. Test for Introspection
    let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;
    let resp = client.inner.post(target)
        .header("Content-Type", "application/json")
        .body(introspection_query)
        .send().await?;
        
    let body = resp.text().await?;
    if body.contains("__schema") && body.contains("types") {
        println!("{} CONFIRMED: GraphQL Introspection Enabled!", "[!]".red().bold());
        println!("    Impact: Full schema exposure allowed");
    }

    // 2. Test for common endpoints if target doesn't look like GraphQL
    if !target.contains("/graphql") {
        let common_endpoints = vec!["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"];
        for ep in common_endpoints {
            let ep_url = format!("{}{}", target.trim_end_matches('/'), ep);
            if let Ok(resp) = client.inner.get(&ep_url).send().await {
                if resp.status().is_success() {
                    println!("{} FOUND: GraphQL endpoint at {}", "[!]".yellow(), ep_url);
                }
            }
        }
    }

    Ok(())
}
