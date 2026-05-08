use std::collections::HashMap;
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub query_params: Vec<(String, String)>,
}

pub struct RequestParser;

impl RequestParser {
    /// Parse a raw HTTP request from a file (Burp Suite format)
    pub fn from_file(file_path: &str) -> Result<RawRequest> {
        let content = fs::read_to_string(file_path)?;
        Self::parse(&content)
    }

    /// Parse raw HTTP request string
    pub fn parse(raw: &str) -> Result<RawRequest> {
        let lines: Vec<&str> = raw.lines().collect();
        if lines.is_empty() {
            return Err(anyhow::anyhow!("Empty request"));
        }

        // 1. Parse Request Line: POST /path?id=1 HTTP/1.1
        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow::anyhow!("Invalid request line"));
        }

        let method = parts[0].to_string();
        let full_path = parts[1].to_string();
        
        // Split path and query params
        let (path, query_params) = if let Some(pos) = full_path.find('?') {
            let p = &full_path[..pos];
            let q = &full_path[pos + 1..];
            let params = q.split('&')
                .filter_map(|pair| {
                    let mut s = pair.splitn(2, '=');
                    Some((s.next()?.to_string(), s.next()?.to_string()))
                })
                .collect();
            (p.to_string(), params)
        } else {
            (full_path, vec![])
        };

        // 2. Parse Headers
        let mut headers = HashMap::new();
        let mut body_start_idx = 1;
        let mut host = String::new();

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.trim().is_empty() {
                body_start_idx = i + 1;
                break;
            }

            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_lowercase();
                let value = line[pos + 1..].trim().to_string();
                
                if key == "host" {
                    host = value.clone();
                }
                headers.insert(key, value);
            }
        }

        // 3. Parse Body
        let body = lines.iter().skip(body_start_idx).cloned().collect::<Vec<&str>>().join("\n");

        Ok(RawRequest {
            method,
            path,
            host,
            headers,
            body,
            query_params,
        })
    }
}
