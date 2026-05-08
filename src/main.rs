use colored::*;
use inquire::{Select, Text};
use std::process;

mod core;
mod modules;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    print_banner();

    let input_methods = vec!["Target URL", "Raw HTTP Request File (Burp)"];
    let input_method = Select::new("Choose input method:", input_methods).prompt()?;

    // ... (target extraction logic remains same)
    let target = if input_method == "Target URL" {
        let t = Text::new("Enter target URL (e.g., https://example.com):")
            .with_placeholder("https://...")
            .prompt()?;
        
        if t.is_empty() {
            println!("{}", "Error: Target URL cannot be empty.".red());
            process::exit(1);
        }
        t
    } else {
        let file_path = Text::new("Enter path to raw request file:")
            .with_placeholder("request.txt")
            .prompt()?;
            
        let raw = core::parser::RequestParser::from_file(&file_path)?;
        let host = raw.headers.get("host").cloned().unwrap_or_default();
        let scheme = if host.contains(":443") { "https" } else { "http" };
        
        let t = format!("{}://{}{}", scheme, host, raw.path);
        println!("{} Parsed Target from file: {}", "[i]".cyan(), t);
        t
    };

    loop {
        let categories = vec![
            "Proxies (Smuggling, Cache, etc.)",
            "User Input (Reflected, Search, Forms, WebSockets)",
            "HTTP Headers (CORS, Clickjacking, CSP)",
            "Bypasses (2FA, Rate Limit, Race Conditions)",
            "Structured Objects (JWT, XXE, GraphQL)",
            "Files (Upload, Formula, PDF Injection)",
            "External Identity (OAuth, SAML)",
            "Infrastructure (Servers, CMS, Frameworks, APIs)",
            "Web3 & Supply Chain",
            "View Full Methodology",
            "Exit",
        ];

        let selection = Select::new("Select a category to scan:", categories).prompt()?;

        match selection {
            "Proxies (Smuggling, Cache, etc.)" => {
                println!("{} Running Proxy Modules...", "[-]".blue());
                if let Err(e) = modules::proxy::run(&target).await {
                    println!("{} Error in Proxy module: {}", "[x]".red(), e);
                }
            }
            "User Input (Reflected, Search, Forms, WebSockets)" => {
                println!("{} Running User Input Modules...", "[-]".blue());
                if let Err(e) = modules::input::run(&target).await {
                    println!("{} Error in User Input module: {}", "[x]".red(), e);
                }
            }
            "HTTP Headers (CORS, Clickjacking, CSP)" => {
                println!("{} Running HTTP Headers Modules...", "[-]".blue());
                if let Err(e) = modules::headers::run(&target).await {
                    println!("{} Error in Headers module: {}", "[x]".red(), e);
                }
            }
            "Bypasses (2FA, Rate Limit, Race Conditions)" => {
                println!("{} Running Bypass Modules...", "[-]".blue());
                if let Err(e) = modules::auth::run(&target).await {
                    println!("{} Error in Bypass module: {}", "[x]".red(), e);
                }
            }
            "Structured Objects (JWT, XXE, GraphQL)" => {
                println!("{} Running Structured Object Modules...", "[-]".blue());
                if let Err(e) = modules::structured::run(&target).await {
                    println!("{} Error in Structured module: {}", "[x]".red(), e);
                }
            }
            "Files (Upload, Formula, PDF Injection)" => {
                println!("{} Running File Modules...", "[-]".blue());
                if let Err(e) = modules::files::run(&target).await {
                    println!("{} Error in Files module: {}", "[x]".red(), e);
                }
            }
            "External Identity (OAuth, SAML)" => {
                println!("{} [i] Identity modules (OAuth/SAML) are in active development.", "[*]".yellow());
            }
            "Infrastructure (Servers, CMS, Frameworks, APIs)" => {
                println!("{} Running Infrastructure Modules...", "[-]".blue());
                if let Err(e) = modules::infra::run(&target).await {
                    println!("{} Error in Infrastructure module: {}", "[x]".red(), e);
                }
            }
            "Web3 & Supply Chain" => {
                println!("{} [i] Web3 & Supply Chain modules are currently experimental.", "[*]".yellow());
            }
            "View Full Methodology" => {
                core::methodology::print_full_methodology();
            }
            "Exit" => {
                println!("{}", "Exiting lazy-recon. Happy hunting!".green());
                break;
            }
            _ => {}
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
