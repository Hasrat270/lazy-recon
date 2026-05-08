use colored::*;

/// Simple reporter for scan findings
pub struct Reporter;

impl Reporter {
    pub fn found(module: &str, detail: &str) {
        println!("{} CONFIRMED: {} — {}", "[!]".red().bold(), module, detail);
    }

    pub fn testing(module: &str) {
        println!("{} Testing: {}", "[*]".yellow(), module);
    }

    pub fn info(msg: &str) {
        println!("{} {}", "[i]".cyan(), msg);
    }

    pub fn none(module: &str) {
        println!("{} {}: No issues detected", "[✓]".green(), module);
    }
}
