use colored::*;

pub fn print_full_methodology() {
    println!("{}", "==========================================================".blue().bold());
    println!("{}", "          WEB VULNERABILITIES METHODOLOGY".blue().bold());
    println!("{}", "==========================================================".blue().bold());

    println!("\n{}", "Tip:".yellow().bold());
    println!("Learn & practice AWS/GCP/Azure Hacking at HackTricks Training.");
    
    println!("\n{}", "Proxies".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("Abusing hop-by-hop headers");
    println!("Cache Poisoning/Cache Deception");
    println!("HTTP Connection Contamination");
    println!("HTTP Connection Request Smuggling");
    println!("HTTP Request Smuggling");
    println!("HTTP Response Smuggling / Desync");
    println!("H2C Smuggling");
    println!("Server Side Inclusion/Edge Side Inclusion");
    println!("Uncovering Cloudflare");
    println!("XSLT Server Side Injection");
    println!("Proxy / WAF Protections Bypass");

    println!("\n{}", "User Input".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("\n{}", "Reflected Values".cyan().bold());
    println!("Client Side Path Traversal");
    println!("Client Side Template Injection");
    println!("Command Injection");
    println!("CRLF");
    println!("Dangling Markup");
    println!("File Inclusion/Path Traversal");
    println!("Open Redirect");
    println!("Prototype Pollution to XSS");
    println!("Server Side Inclusion/Edge Side Inclusion");
    println!("Server Side Request Forgery");
    println!("Server Side Template Injection");
    println!("Reverse Tab Nabbing");
    println!("XSLT Server Side Injection");
    println!("XSS");
    println!("XSSI");
    println!("XS-Search");

    println!("\n{}", "Search Functionalities".cyan().bold());
    println!("File Inclusion/Path Traversal");
    println!("NoSQL Injection");
    println!("LDAP Injection");
    println!("ReDoS");
    println!("SQL Injection");
    println!("ORM Injection");
    println!("RSQL Injection");
    println!("XPATH Injection");

    println!("\n{}", "Forms, WebSockets and PostMsgs".cyan().bold());
    println!("Cross Site Request Forgery");
    println!("Cross-site WebSocket hijacking (CSWSH)");
    println!("Phone Number Injections");
    println!("PostMessage Vulnerabilities");

    println!("\n{}", "HTTP Headers".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("Clickjacking");
    println!("Iframe Traps / Click Isolation");
    println!("Content Security Policy bypass");
    println!("Cookies Hacking");
    println!("CORS - Misconfigurations & Bypass");

    println!("\n{}", "Bypasses".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("2FA/OTP Bypass");
    println!("Bypass Payment Process");
    println!("Captcha Bypass");
    println!("Account Takeover Playbooks");
    println!("Login Bypass");
    println!("Race Condition");
    println!("Rate Limit Bypass");
    println!("Reset Forgotten Password Bypass");
    println!("Registration Vulnerabilities");

    println!("\n{}", "Structured Objects".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("Deserialization");
    println!("Email Header Injection");
    println!("JWT Vulnerabilities");
    println!("JSON / XML / YAML Hacking");
    println!("XML External Entity");
    println!("GraphQL Attacks");
    println!("gRPC-Web Attacks");

    println!("\n{}", "Files".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("File Upload");
    println!("Formula Injection");
    println!("PDF Injection");
    println!("Server Side XSS");

    println!("\n{}", "External Identity Management".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("OAUTH to Account takeover");
    println!("SAML Attacks");

    println!("\n{}", "Other Helpful Vulnerabilities".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("Domain/Subdomain takeover");
    println!("IDOR");
    println!("Mass Assignment (CWE-915)");
    println!("Parameter Pollution");
    println!("Unicode Normalization vulnerability");

    println!("\n{}", "Infrastructure & Frameworks".magenta().bold());
    println!("{}", "----------------------------------------------------------".magenta());
    println!("Web Servers (Apache, Nginx, IIS, Tomcat)");
    println!("Spring Actuators");
    println!("Application Frameworks (Django, Flask, Node, Laravel, etc.)");
    println!("CMS (WordPress, Joomla, Drupal, etc.)");
    println!("APIs, Buckets & Integrations");
    println!("Supply Chain & timing Attacks");
    println!("Web3 & dApps");

    println!("\n{}", "==========================================================".blue().bold());
}
