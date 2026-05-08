use colored::*;

/// Real-time scanner feedback utilities
#[allow(dead_code)]
pub struct Reporter;

#[allow(dead_code)]
impl Reporter {
    /// Report a confirmed vulnerability
    pub fn found(module: &str, detail: &str) {
        println!("{} {} — {}", "[!]".red().bold(), module.red().bold(), detail);
    }

    /// Update on current test progress
    pub fn progress(msg: &str) {
        println!("{} {}", "[>]".cyan(), msg);
    }

    /// Report a successful but not necessarily vulnerable check
    pub fn success(msg: &str) {
        println!("{} {}", "[+]".green(), msg);
    }

    /// Status update
    pub fn info(msg: &str) {
        println!("{} {}", "[*]".blue(), msg);
    }
}
