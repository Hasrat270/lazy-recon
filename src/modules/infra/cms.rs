use colored::*;
use crate::core::client::HttpClient;

/// CMS detection (WordPress, Joomla, Drupal)
pub async fn detect(target: &str) -> anyhow::Result<()> {
    println!("{} Testing: CMS Detection", "[*]".yellow());

    let client = HttpClient::new()?;
    
    let cms_list = vec![
        ("WordPress", vec!["/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-json/"]),
        ("Joomla", vec!["/administrator/", "/components/", "/templates/joomla/"]),
        ("Drupal", vec!["/sites/default/", "/core/"]),
        ("Moodle", vec!["/moodle/", "/theme/standard/"]),
    ];

    for (name, paths) in cms_list {
        for path in paths {
            let url = format!("{}{}", target.trim_end_matches('/'), path);
            if let Ok(resp) = client.inner.get(&url).send().await {
                if resp.status().is_success() {
                    println!("{} FOUND: {} detected via path {}", "[!]".red(), name, path);
                    break;
                }
            }
        }
    }

    Ok(())
}
