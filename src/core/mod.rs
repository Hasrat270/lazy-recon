pub mod crawler;
pub mod client;
pub mod analyzer;
pub mod reporter;
pub mod methodology;
pub mod errors;
pub mod parser;

use std::sync::Mutex;
use once_cell::sync::Lazy;

pub struct Config {
    pub proxy_url: Option<String>,
}

pub static GLOBAL_CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| {
    Mutex::new(Config {
        proxy_url: None,
    })
});
