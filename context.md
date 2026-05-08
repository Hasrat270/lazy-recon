# lazy-recon: Project Context

**Status:** Active Development
**Methodology:** Automated Web Vulnerability Methodology (Based on `Web_Methodology.txt`)

## 🛠 Tech Stack
- **Language:** Rust (edition 2021)
- **Runtime:** `tokio` (Async/Concurrent)
- **Networking:** `reqwest` (standard), `hyper` & `tokio::net` (Raw TCP/TLS for Smuggling)
- **UI:** `inquire` (Interactive CLI), `colored` (Aesthetics)

### 4. Bypasses (Auth) [COMPLETE: 4/4]
Implemented detection for:
1.  **Rate Limit Bypass** (IP spoofing headers)
2.  **Race Condition** (Concurrent request testing)
3.  **Login Bypass** (SQLi/NoSQLi on auth params)
4.  **OTP Bypass** (Weak code testing)

## 📂 Project Structure
```text
lazy-recon/
├── Cargo.toml          # High-performance dependencies
├── context.md          # This file (Current state & context)
├── src/
│   ├── main.rs         # Interactive CLI & Entry point
│   ├── core/           # Engines (HttpClient, RawClient, Analyzer, Reporter)
│   └── modules/        # Methodology Categories
│       ├── proxy/      # 11 Proxy modules implemented
│       ├── input/      # 24 User Input modules implemented
│       ├── headers/    # 4 HTTP Header modules implemented
│       ├── auth/       # 4 Bypass/Auth modules implemented
│       └── structured/ # [NEXT] Structured Objects (JWT, XXE, etc.)
```

## 🎯 Next Objective
**Category:** Structured Objects
- Implement detection for JWT vulnerabilities, XXE, and Deserialization issues.

