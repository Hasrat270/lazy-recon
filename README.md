# 🛠️ lazy-recon

**High-Performance, Modular Web Vulnerability Scanner**

`lazy-recon` is a professional-grade security tool written in Rust, designed to automate comprehensive web security methodologies. It focuses on high-fidelity detection with low false positives by utilizing algorithmic proof-of-concept (PoC) generation.

---

## 🚀 Features

The scanner implements **65+ modules** across 8 core methodology categories:

1.  **Proxies & Smuggling**: Request Smuggling (CL.TE/TE.CL), H2C Smuggling, Cache Poisoning, Hop-by-Hop abuse.
2.  **User Input Analysis**: Advanced detection for XSS, SQLi, NoSQLi, SSTI, Command Injection, SSRF, and Path Traversal.
3.  **Logic & Auth Bypasses**: IDOR, Mass Assignment, Rate Limit Bypass, Race Conditions, OAuth/SAML vulnerabilities.
4.  **Structured Objects**: JWT security audits, XXE (XML External Entity), Deserialization flaws, GraphQL introspection.
5.  **HTTP Headers**: CSP Bypass analysis, CORS misconfigurations, Cookie security (HttpOnly/Secure/SameSite).
6.  **File Operations**: File Upload bypasses, Formula Injection (CSV/Excel), PDF Injection.
7.  **Infrastructure & Middleware**: Web server misconfigs (PUT method, Directory Listing), Spring Actuators, Cloud Bucket exposure.
8.  **Modern Web Discovery**: API endpoint discovery (Swagger/Docs), CMS & Framework fingerprinting, Domain Takeover.

---

## 🛠️ Architecture

Built for speed and protocol-level control:
- **Core Engine**: Custom TCP/TLS client for low-level smuggling and connection contamination attacks.
- **Asynchronous**: Built on `tokio` for concurrent scanning across multiple parameters and modules.
- **PoC Driven**: Not just a fuzzer; it analyzes responses to confirm impact.

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/Hasrat270/lazy-recon.git
cd lazy-recon

# Build the project
cargo build --release
```

## 🎯 Usage

```bash
# Run the interactive CLI
cargo run
```

1. Enter the target URL (e.g., `https://example.com`).
2. Select the methodology category to scan.
3. Review the real-time findings with color-coded impact levels.

---

## ⚠️ Disclaimer

*This tool is for educational and professional security testing purposes only. Unauthorized scanning of targets is illegal. The author is not responsible for any misuse or damage caused by this tool.*

---

**Happy Hunting!** 🛡️
