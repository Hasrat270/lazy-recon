use scraper::{Html, Selector};
use url::Url;
use std::collections::HashSet;
use dashmap::DashSet;
use std::sync::Arc;
use crate::core::client::HttpClient;
use colored::*;
use regex::Regex;

pub struct Crawler {
    base_url: Url,
    visited: Arc<DashSet<String>>,
    client: HttpClient,
}

impl Crawler {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let mut url_str = base_url.to_string();
        if !url_str.contains("://") {
            url_str = format!("https://{}", url_str);
        }
        let url = Url::parse(&url_str)?;
        Ok(Self {
            base_url: url,
            visited: Arc::new(DashSet::new()),
            client: HttpClient::new()?,
        })
    }

    pub async fn crawl(&self, max_depth: usize) -> anyhow::Result<Vec<String>> {
        println!("{} Starting army-style crawling on: {}", "[-]".blue(), self.base_url);
        let mut found_urls = HashSet::new();
        
        // Always include the base URL
        found_urls.insert(self.base_url.to_string());
        
        let mut current_level = vec![self.base_url.to_string()];
        
        for depth in 0..max_depth {
            println!("{} Crawling depth {}/{}...", "[*]".yellow(), depth + 1, max_depth);
            let mut next_level = Vec::new();
            
            for url_str in current_level {
                if self.visited.contains(&url_str) && depth > 0 { continue; }
                self.visited.insert(url_str.clone());
                
                if let Ok(links) = self.get_links(&url_str).await {
                    for link in links {
                        if !found_urls.contains(&link) {
                            found_urls.insert(link.clone());
                            next_level.push(link);
                        }
                    }
                }
            }
            
            if next_level.is_empty() { break; }
            current_level = next_level;
        }

        // --- DISCOVERY FALLBACK (The "Army" part) ---
        // If crawler finds nothing (common in SPAs), we brute force common endpoints
        if found_urls.len() <= 1 {
            println!("{} Static crawler found no links. Activating 'Army Discovery' fallback...", "[!]".yellow());
            let common_paths = vec![
                "/api", "/v1", "/v2", "/admin", "/login", "/signup", "/dashboard", 
                "/config", "/user", "/settings", "/api/v1", "/graphql", "/wp-json",
                "/static", "/assets", "/debug", "/info", "/status"
            ];
            
            for path in common_paths {
                if let Ok(full_url) = self.base_url.join(path) {
                    let url_s = full_url.to_string();
                    if !found_urls.contains(&url_s) {
                        if let Ok(resp) = self.client.inner.get(&url_s).send().await {
                            let status = resp.status().as_u16();
                            if status == 200 || status == 302 || status == 403 || status == 401 {
                                println!("{} Discovered path: {} [{}]", "[+]".green(), path, status);
                                found_urls.insert(url_s);
                            }
                        }
                    }
                }
            }
        }

        println!("{} Crawling finished. Found {} unique targets.", "[+]".green(), found_urls.len());
        Ok(found_urls.into_iter().collect())
    }

    async fn get_links(&self, url_str: &str) -> anyhow::Result<Vec<String>> {
        let resp = self.client.inner.get(url_str).send().await?;
        if !resp.status().is_success() { return Ok(vec![]); }
        
        let body = resp.text().await?;
        let mut links = Vec::new();
        let base_domain = self.base_url.domain().unwrap_or_default();

        // 1. Standard HTML <a> tags
        let document = Html::parse_document(&body);
        let a_selector = Selector::parse("a[href]").unwrap();
        for element in document.select(&a_selector) {
            if let Some(href) = element.value().attr("href") {
                self.push_if_valid(&mut links, href, base_domain);
            }
        }

        // 2. JavaScript / Script tags discovery (Regex for paths like "/api/...")
        // This is crucial for SPAs like 1win.com
        let re_path = Regex::new(r#"(?i)["'](/[a-z0-9/_-]{2,})["']"#).unwrap();
        for cap in re_path.captures_iter(&body) {
            let path = &cap[1];
            self.push_if_valid(&mut links, path, base_domain);
        }

        // 3. Form actions
        let form_selector = Selector::parse("form[action]").unwrap();
        for element in document.select(&form_selector) {
            if let Some(action) = element.value().attr("action") {
                self.push_if_valid(&mut links, action, base_domain);
            }
        }
        
        Ok(links)
    }

    fn push_if_valid(&self, links: &mut Vec<String>, href: &str, base_domain: &str) {
        if let Ok(absolute_url) = self.base_url.join(href) {
            if absolute_url.domain() == Some(base_domain) {
                let mut final_url = absolute_url.clone();
                final_url.set_fragment(None);
                links.push(final_url.to_string());
            }
        }
    }

    pub async fn run_army_attack(target_url: &str) -> anyhow::Result<()> {
        let crawler = Self::new(target_url)?;
        let discovered_urls = crawler.crawl(2).await?;
        
        println!("\n{}", "==================================================".red().bold());
        println!("{}", "      ARMY ATTACK: SCANNING ALL DISCOVERED URLS".red().bold());
        println!("{}\n", "==================================================".red().bold());

        for url in discovered_urls {
            println!("\n{} Target: {}", ">>>".red().bold(), url.bright_white().bold());
            
            // Run high-priority modules for each URL
            let _ = crate::modules::proxy::run(&url).await;
            let _ = crate::modules::input::run(&url).await;
            let _ = crate::modules::headers::run(&url).await;
        }

        Ok(())
    }
}
