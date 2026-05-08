use colored::*;
use inquire::{Select, Text};
use std::process;

mod core;
mod modules;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    print_banner();

    let target = Text::new("Enter target URL (e.g., https://example.com):")
        .with_placeholder("https://...")
        .prompt()?;

    if target.is_empty() {
        println!("{}", "Error: Target URL cannot be empty.".red());
        process::exit(1);
    }

    loop {
        let categories = vec![
            "Proxies (Smuggling, Cache, etc.)",
            "User Input (XSS, SSTI, SQLi)",
            "HTTP Headers (CORS, CSP)",
            "Bypasses (2FA, Rate Limit)",
            "Structured Objects (JWT, GraphQL)",
            "Files (Upload, Formula Injection)",
            "Infrastructure (Servers, CMS, Frameworks)",
            "Exit",
        ];

        let selection = Select::new("Select a category to scan:", categories).prompt()?;

        match selection {
            "Proxies (Smuggling, Cache, etc.)" => {
                println!("{} Running Proxy Modules...", "[-]".blue());
                modules::proxy::run(&target).await?;
            }
            "User Input (XSS, SSTI, SQLi)" => {
                println!("{} Running User Input Modules...", "[-]".blue());
                modules::input::run(&target).await?;
            }
            "HTTP Headers (CORS, CSP)" => {
                println!("{} Running HTTP Headers Modules...", "[-]".blue());
                modules::headers::run(&target).await?;
            }
            "Bypasses (2FA, Rate Limit)" => {
                println!("{} Running Bypass Modules...", "[-]".blue());
                modules::auth::run(&target).await?;
            }
            "Structured Objects (JWT, GraphQL)" => {
                println!("{} Running Structured Object Modules...", "[-]".blue());
                modules::structured::run(&target).await?;
            }
            "Files (Upload, Formula Injection)" => {
                println!("{} Running File Modules...", "[-]".blue());
                modules::files::run(&target).await?;
            }
            "Infrastructure (Servers, CMS, Frameworks)" => {
                println!("{} Running Infrastructure Modules...", "[-]".blue());
                modules::infra::run(&target).await?;
            }
            "Exit" => {
                println!("{}", "Exiting lazy-recon. Happy hunting!".green());
                break;
            }
        }
    }

    Ok(())
}

fn print_banner() {
    let banner = r#"
    __                      ____                      
   / /   ____ _____  __  __/ __ \___  _________  ____ 
  / /   / __ `/_  / / / / / /_/ / _ \/ ___/ __ \/ __ \
 / /___/ /_/ / / /_/ /_/ / _, _/  __/ /__/ /_/ / / / /
/_____/\__,_/ /___/\__, /_/ |_|\___/\___/\____/_/ /_/ 
                  /____/                              
    "#;
    println!("{}", banner.cyan().bold());
    println!("{}", "   --- Professional Methodology Automator ---".white().italic());
    println!();
}
