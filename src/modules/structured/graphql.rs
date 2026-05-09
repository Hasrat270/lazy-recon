use colored::*;
use crate::core::client::HttpClient;
use crate::core::reporter::Reporter;

/// GraphQL vulnerability detection (Introspection, Circular Queries, etc.)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: GraphQL Attacks", "[*]".yellow());

    let client = HttpClient::new()?;
    
    // 1. Test for Introspection
    let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;
    if let Ok(resp) = client.inner.post(target)
        .header("Content-Type", "application/json")
        .body(introspection_query)
        .send().await 
    {
        let body = resp.text().await?;
        if body.contains("__schema") && body.contains("types") {
            Reporter::found("GraphQL Introspection", "Full schema exposure is enabled", &format!("POST to {} with body: {}", target, introspection_query));
        }
    }

    // 2. Test for common endpoints
    let common_endpoints = vec!["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"];
    for ep in common_endpoints {
        let ep_url = format!("{}{}", target.trim_end_matches('/'), ep);
        if let Ok(resp) = client.inner.get(&ep_url).send().await {
            if resp.status().is_success() {
                Reporter::found("GraphQL Endpoint Found", &format!("Endpoint discovered at {}", ep_url), &format!("Try accessing {} in your browser or via Burp.", ep_url));
            }
        }
    }

    Ok(())
}
