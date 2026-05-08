#!/bin/bash
git init
git remote add origin https://github.com/Hasrat270/lazy-recon.git
git add .
git commit -m "Initial commit: Core engine, analyzer and first batch of vulnerability modules (Proxies, User Input, Headers, Bypasses)"
git branch -M main
git push -u origin main
