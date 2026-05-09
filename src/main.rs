use colored::*;
use inquire::{Select, Text};
use std::process;
use tokio::signal;

mod core;
mod modules;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup Graceful Shutdown (Ctrl+C)
    tokio::spawn(async {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!("\n\n{}", "!!! Interrupt received. Cleaning up and exiting gracefully...".red().bold());
        println!("{}", "Exiting lazy-recon. Happy hunting!".green());
        process::exit(0);
    });

    print_banner();

    let input_methods = vec![
        "Target URL", 
        "Raw HTTP Request File (Burp)",
        "Full Web Crawler (Army Attack)"
    ];
    let input_method = Select::new("Choose input method:", input_methods).prompt()?;
    println!(); // Add spacing

    // Proxy Selection
    let use_proxy = Select::new("Do you want to route traffic through a proxy (e.g. Burp Suite)?", vec!["No", "Yes"]).prompt()?;
    if use_proxy == "Yes" {
        let proxy_addr = Text::new("Enter proxy address:")
            .with_default("http://127.0.0.1:8080")
            .prompt()?;
        
        if let Ok(mut config) = core::GLOBAL_CONFIG.lock() {
            config.proxy_url = Some(proxy_addr);
            println!("{} Upstream Proxy set to {}", "[i]".cyan(), config.proxy_url.as_ref().unwrap());
        }
        println!();
    }

    // Target Selection
    let target = if input_method == "Target URL" || input_method == "Full Web Crawler (Army Attack)" {
        let t = Text::new("Enter target URL (e.g., https://example.com):")
            .with_placeholder("https://...")
            .prompt()?;
        println!(); // Add spacing
        
        if t.is_empty() {
            println!("{}", "Error: Target URL cannot be empty.".red());
            process::exit(1);
        }
        t
    } else {
        let file_path = Text::new("Enter path to raw request file:")
            .with_placeholder("request.txt")
            .prompt()?;
        println!(); // Add spacing
        
        let path = std::path::Path::new(&file_path);
        if !path.is_file() {
            println!("{} Error: '{}' is not a valid file. Please provide a path to a raw HTTP request text file.", "[x]".red(), file_path);
            process::exit(1);
        }
            
        let raw = core::parser::RequestParser::from_file(&file_path)?;
        let host = raw.headers.get("host").cloned().unwrap_or_default();
        let scheme = if host.contains(":443") { "https" } else { "http" };
        
        let t = format!("{}://{}{}", scheme, host, raw.path);
        println!("{} Parsed Target from file: {}\n", "[i]".cyan(), t);
        t
    };

    if input_method == "Full Web Crawler (Army Attack)" {
        core::crawler::Crawler::run_army_attack(&target).await?;
        println!("\n{}", "Army Attack completed. All discovered paths scanned.".green().bold());
        return Ok(());
    }

    println!(); // Spacing before category selection
    loop {
        let categories = vec![
            format!("{} {}", "🌐", "Proxies (Smuggling, Cache, etc.)").white().bold().to_string(),
            format!("{} {}", "⌨️ ", "User Input (Reflected, Search, Forms, WebSockets)").white().bold().to_string(),
            format!("{} {}", "🛡️ ", "HTTP Headers (CORS, Clickjacking, CSP)").white().bold().to_string(),
            format!("{} {}", "🔐", "Bypasses (2FA, Rate Limit, Race Conditions)").white().bold().to_string(),
            format!("{} {}", "📦", "Structured Objects (JWT, XXE, GraphQL)").white().bold().to_string(),
            format!("{} {}", "📁", "Files (Upload, Formula, PDF Injection)").white().bold().to_string(),
            format!("{} {}", "🆔", "External Identity (OAuth, SAML)").white().bold().to_string(),
            format!("{} {}", "🏗️ ", "Infrastructure (Servers, CMS, Frameworks, APIs)").white().bold().to_string(),
            format!("{} {}", "🔗", "Web3 & Supply Chain").white().bold().to_string(),
            format!("{} {}", "📖", "View Full Methodology").white().bold().to_string(),
            format!("{} {}", "🚪", "Exit").red().bold().to_string(),
        ];

        let selection = Select::new("Select a category to scan:", categories.clone())
            .with_page_size(15)
            .prompt()?;
        
        println!(); // Space after selection
        
        // Find index of selection in original list to match
        let selected_index = categories.iter().position(|r| r == &selection).unwrap_or(0);
        
        match selected_index {
            0 => {
                println!("{} Running Proxy Modules...\n", "[-]".blue());
                if let Err(e) = modules::proxy::run(&target).await {
                    println!("{} Error in Proxy module: {}", "[x]".red(), e);
                }
            }
            1 => {
                println!("{} Running User Input Modules...\n", "[-]".blue());
                if let Err(e) = modules::input::run(&target).await {
                    println!("{} Error in User Input module: {}", "[x]".red(), e);
                }
            }
            2 => {
                println!("{} Running HTTP Headers Modules...\n", "[-]".blue());
                if let Err(e) = modules::headers::run(&target).await {
                    println!("{} Error in Headers module: {}", "[x]".red(), e);
                }
            }
            3 => {
                println!("{} Running Bypass Modules...\n", "[-]".blue());
                if let Err(e) = modules::auth::run(&target).await {
                    println!("{} Error in Bypass module: {}", "[x]".red(), e);
                }
            }
            4 => {
                println!("{} Running Structured Object Modules...\n", "[-]".blue());
                if let Err(e) = modules::structured::run(&target).await {
                    println!("{} Error in Structured module: {}", "[x]".red(), e);
                }
            }
            5 => {
                println!("{} Running File Modules...\n", "[-]".blue());
                if let Err(e) = modules::files::run(&target).await {
                    println!("{} Error in Files module: {}", "[x]".red(), e);
                }
            }
            6 => {
                println!("{} [i] Identity modules (OAuth/SAML) are in active development.\n", "[*]".yellow());
            }
            7 => {
                println!("{} Running Infrastructure Modules...\n", "[-]".blue());
                if let Err(e) = modules::infra::run(&target).await {
                    println!("{} Error in Infrastructure module: {}", "[x]".red(), e);
                }
            }
            8 => {
                println!("{} [i] Web3 & Supply Chain modules are currently experimental.\n", "[*]".yellow());
            }
            9 => {
                core::methodology::print_full_methodology();
            }
            10 => {
                println!("{}", "Exiting lazy-recon. Happy hunting!".green());
                break;
            }
            _ => {}
        }
        println!("\n{}", "--------------------------------------------------".white().dimmed());
        println!(); // Space before next loop
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
