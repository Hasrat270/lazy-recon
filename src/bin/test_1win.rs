use lazy_recon::core::client::HttpClient;
use lazy_recon::core::crawler::Crawler;
use lazy_recon::modules::proxy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let target = "https://1win.com/";
    println!("--- Debug Scan against {} ---", target);

    // 1. Test Crawler
    let client = HttpClient::new()?;
    let mut crawler = Crawler::new(target, client)?;
    let found = crawler.crawl(1).await?;
    println!("\n[+] Crawler found {} URLs", found.len());
    for url in found.iter().take(10) {
        println!("  - {}", url);
    }

    // 2. Run Proxy Modules (only first few to check for errors)
    println!("\n[*] Running Proxy Modules...");
    proxy::run(target).await?;

    Ok(())
}
