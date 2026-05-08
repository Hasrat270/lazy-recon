# lazy-recon: Project Context

**Status:** Active Development
**Methodology:** Automated Web Vulnerability Methodology (Based on `Web_Methodology.txt`)

## 🛠 Tech Stack
- **Language:** Rust (edition 2021)
- **Runtime:** `tokio` (Async/Concurrent)
- **Networking:** `reqwest` (standard), `hyper` & `tokio::net` (Raw TCP/TLS for Smuggling)
- **UI:** `inquire` (Interactive CLI), `colored` (Aesthetics)

### 1. Proxies [COMPLETE: 11/11]
### 2. User Input [COMPLETE: 30/30]
### 3. HTTP Headers [COMPLETE: 4/4]
### 4. Bypasses & Auth [COMPLETE: 6/6]
### 5. Structured Objects [COMPLETE: 4/4]
### 6. Files [COMPLETE: 3/3]
### 7. Logic & Discovery [COMPLETE: 4/4]
### 8. Infrastructure & Middleware [COMPLETE: 7/7]

## 📂 Project Structure
```text
lazy-recon/
├── Cargo.toml          # High-performance dependencies
├── context.md          # Complete project overview
├── src/
│   ├── main.rs         # Interactive CLI & Entry point
│   ├── core/           # Engines (HttpClient, RawClient, Analyzer, Reporter)
│   └── modules/        # Methodology Categories (ALL COMPLETE)
│       ├── proxy/      # 11 Modules
│       ├── input/      # 30 Modules (Reflected, Search, Logic)
│       ├── headers/    # 4 Modules
│       ├── auth/       # 6 Modules (OAuth, SAML included)
│       ├── structured/ # 4 Modules (JWT, XXE, etc.)
│       ├── files/      # 3 Modules
│       └── infra/      # 7 Modules
```

## 🎯 Status
**Full Methodology Implemented.**
The scanner now covers over 65+ specific vulnerability types across all major categories of the Web Security Checklist.

