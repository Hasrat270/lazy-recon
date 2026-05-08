use url::Url;
use crate::core::client::HttpClient;
use std::collections::HashMap;
use std::time::Instant;
use serde_json::Value;

/// Result of injecting a payload into a parameter
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InjectionResult {
    pub param: String,
    pub reflected_in_body: bool,
    pub reflected_in_headers: bool,
    pub response_body: String,
    pub response_headers: HashMap<String, String>,
    pub status_code: u16,
    pub response_time_ms: u128,
}

/// Shared reflection and injection analysis utilities
pub struct Analyzer;

impl Analyzer {
    /// Extract query parameters from a URL
    pub fn extract_params(target: &str) -> Vec<(String, String)> {
        Url::parse(target)
            .map(|url| url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect())
            .unwrap_or_default()
    }

    /// Extract parameters from a RawRequest (Query + Body)
    #[allow(dead_code)]
    pub fn extract_params_from_raw(raw: &crate::core::parser::RawRequest) -> Vec<(String, String)> {
        // ... (existing logic)
        let mut params = raw.query_params.clone();
        
        // Extract from body if it's form-data or JSON
        let ct = raw.headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
        if ct.contains("application/x-www-form-urlencoded") {
            let body_params = raw.body.split('&')
                .filter_map(|pair| {
                    let mut s = pair.splitn(2, '=');
                    Some((s.next()?.to_string(), s.next()?.to_string()))
                });
            params.extend(body_params);
        } else if ct.contains("application/json") {
            if let Ok(Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&raw.body) {
                for (k, v) in map {
                    params.push((k, v.to_string().replace('"', "")));
                }
            }
        }
        
        params
    }

    /// Build a URL with one parameter replaced by a payload
    pub fn inject_param(target: &str, param_name: &str, payload: &str) -> anyhow::Result<String> {
        let mut url = Url::parse(target)?;
        let params: Vec<(String, String)> = url.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        {
            let mut pairs = url.query_pairs_mut();
            pairs.clear();
            for (k, v) in &params {
                if k == param_name {
                    pairs.append_pair(k, payload);
                } else {
                    pairs.append_pair(k, v);
                }
            }
        }
        Ok(url.to_string())
    }

    /// Send a GET request and analyze the response
    pub async fn send_and_analyze(
        client: &HttpClient,
        url: &str,
        check: &str,
    ) -> anyhow::Result<InjectionResult> {
        let start = Instant::now();
        let resp = client.inner.get(url).send().await?;
        let elapsed = start.elapsed().as_millis();
        let status = resp.status().as_u16();

        let mut resp_headers = HashMap::new();
        for (name, value) in resp.headers().iter() {
            resp_headers.insert(
                name.to_string(),
                value.to_str().unwrap_or("").to_string(),
            );
        }

        let body = resp.text().await?;

        Ok(InjectionResult {
            param: String::new(),
            reflected_in_body: !check.is_empty() && body.contains(check),
            reflected_in_headers: !check.is_empty() && resp_headers.values().any(|v| v.contains(check)),
            response_body: body,
            response_headers: resp_headers,
            status_code: status,
            response_time_ms: elapsed,
        })
    }

    /// Test all URL params with a payload and return hits
    pub async fn test_all_params(
        target: &str,
        payload: &str,
        check: &str,
    ) -> anyhow::Result<Vec<InjectionResult>> {
        let client = HttpClient::new()?;
        let params = Self::extract_params(target);
        let mut results = vec![];

        for (param_name, _) in &params {
            let url = Self::inject_param(target, param_name, payload)?;
            if let Ok(mut result) = Self::send_and_analyze(&client, &url, check).await {
                if result.reflected_in_body || result.reflected_in_headers {
                    result.param = param_name.clone();
                    results.push(result);
                }
            }
        }

        Ok(results)
    }

    /// Get baseline response for comparison-based detection
    pub async fn baseline(target: &str) -> anyhow::Result<InjectionResult> {
        let client = HttpClient::new()?;
        Self::send_and_analyze(&client, target, "").await
    }

    /// Test a timed payload — returns (param, response_time_ms)
    pub async fn test_timed(
        target: &str,
        param_name: &str,
        payload: &str,
    ) -> anyhow::Result<u128> {
        let client = HttpClient::new()?;
        let url = Self::inject_param(target, param_name, payload)?;
        let result = Self::send_and_analyze(&client, &url, "").await?;
        Ok(result.response_time_ms)
    }
}
