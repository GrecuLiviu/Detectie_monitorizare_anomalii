# Detection and Monitoring Anomalies in Networks Telecommunications

A professional, full-stack security monitoring and anomaly detection dashboard for telecommunications networks. Built as a final year project in Engineering and Computer Science.

---

## Table of Contents
- [Overview](#overview)
- [Architecture & Deployment](#architecture--deployment)
- [Features](#features)
- [Dashboard UI & Real-Time Metrics](#dashboard-ui--real-time-metrics)
  - [Metric Charts Initialization and Real-Time Updates](#metric-charts-initialization-and-real-time-updates)
- [Setup & Installation](#setup--installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security](#security)
  - [Rate Limiting](#rate-limiting)
  - [CSRF Token Management](#csrf-token-management)
  - [HTTPS and TLS Security](#https-and-tls-security)
  - [Session Security](#session-security)
  - [2FA](#2fa)
  - [Static File Protection](#static-file-protection)
  - [Input Validation](#input-validation)
- [AI Integration](#ai-integration)
- [PDF & Data Export](#pdf--data-export)
- [Customization & Branding](#customization--branding)
- [API Endpoints](#api-endpoints)
- [Scripts & Utilities](#scripts--utilities)
- [Suricata Custom Rules](#suricata-custom-rules)
- [Reliability & Monitoring](#reliability--monitoring)
- [Troubleshooting](#troubleshooting)
- [Middleware](#middleware)
- [Contributing](#contributing)
- [License](#license)

---

## Overview
This project provides a real-time dashboard for detecting, monitoring, and analyzing security anomalies in telecommunications networks. It integrates Suricata IDS, Apache monitoring, geolocation, and AI-powered analysis, with a modern web UI and secure backend. Custom Suricata rules and automated attack scripts allow for realistic testing and demonstration.

## Architecture & Deployment

**System Components:**
- **Linux Mint VM:** Runs Apache server (with DVWA) and Suricata IDS (with custom detection rules).
- **Kali Linux VM:** Runs 5 automated attack scripts: SQL Injection, Command Injection, Port Scan, XSS, and DDoS.
- **Host Machine (Windows):** Runs the Node.js web application, connects to Linux Mint via SSH, and displays data in real time using Secure WebSocket.

**Data Flow:**
```
Kali VM (Attacks)
   │
   ▼
Linux Mint VM (Suricata IDS + Apache)
   │
   │  (SSH, Suricata logs)
   ▼
Host (Node.js App)
   │
   │  (WebSocket, HTTPS)
   ▼
Browser Dashboard
```

**Security:** TLS 1.3, custom certificates, CSP, CSRF, rate limiting, secure WebSocket.

## Features
- Real-time alert and anomaly monitoring (Suricata IDS, custom rules)
- Apache server health and metrics
- Interactive charts: traffic, severity, categories, geolocation
- AI-powered chat for log/event analysis (Ollama integration)
- PDF report generation with custom branding
- CSV/JSON export of alerts
- Telegram notifications for critical alerts
- User authentication with 2FA (TOTP, backup codes)
- Per-route rate limiting for sensitive endpoints
- CSRF protection and secure session management
- SSH reconnection logic for reliability
- Attack simulation with automated scripts (Kali)

## Dashboard UI & Real-Time Metrics

### Metric Charts Initialization and Real-Time Updates

The dashboard features real-time metric charts for CPU, memory, disk usage, and system load averages. These charts are initialized on page load using Chart.js with predefined styles and dimensions for a consistent UI. The frontend receives live metric data from the backend via a secure WebSocket connection. As new data arrives, the charts' datasets are updated in place, maintaining a rolling window of recent values for smooth, real-time visualization. This allows users to monitor server health and performance trends directly from the dashboard.

## Setup & Installation
1. Clone the repository.
2. Install dependencies:
   ```sh
   npm install
   ```
3. Configure environment variables (see `.env.example`).
4. Start the server:
   ```sh
   npm start
   ```
5. Access the dashboard at `https://localhost:3000` (default).

## Configuration
- All configuration is via environment variables and `server/config.js`.
- Key variables: database credentials, session secret, Suricata log path, Telegram bot token, etc.
- See `.env.example` for a full list.

## Usage
- Log in with your credentials (admin user can be created via script).
- 2FA setup via QR code and backup codes.
- View real-time alerts, trends, and server metrics.
- Use the AI chat for event analysis and recommendations.
- Export data or generate branded PDF reports as needed.
- Filter alerts by severity, view as table or JSON, and analyze with AI.
- Export map snapshots as PNG.

## Security
- Per-route rate limiting (login, 2FA, etc.)
- CSRF protection (token-based)
- Secure session cookies (httpOnly, sameSite, secure)
- 2FA (TOTP) for user accounts, with backup codes
- Static file protection
- Input validation and sanitization
- TLS 1.3 with custom-signed certificates

### Rate Limiting

To protect against brute-force attacks and abuse, the application implements per-route rate limiting. Sensitive endpoints such as login and 2FA verification have stricter limits. The rate limiting is configured in `server/config.js` and uses the `express-rate-limit` middleware. This ensures that even if an attacker knows a valid username, they cannot easily guess the password or bypass 2FA.

### CSRF Token Management

To protect against cross-site request forgery (CSRF) attacks, the application uses token-based CSRF protection. On initialization, the frontend fetches a CSRF token from the `/api/csrf-token` endpoint and stores it in a meta tag. All subsequent API requests from the frontend automatically include this token in the `CSRF-Token` header, ensuring that only legitimate, user-initiated actions are processed by the backend. This mechanism is enforced for all non-public routes and is fully integrated into the dashboard's request logic.

### HTTPS and TLS Security

The backend server enforces strong HTTPS security by using custom SSL/TLS certificates and explicitly configuring only modern, secure protocol versions (TLS 1.2 and 1.3). The server restricts connections to a set of robust cipher suites and enforces the server's preferred cipher order, preventing the use of weak or outdated encryption methods. This ensures all data in transit between the dashboard and backend is encrypted and protected against eavesdropping or tampering.

### Session Security

Session security is maintained through secure, httpOnly, and sameSite cookies. The session middleware is configured to use strong secrets and regenerate the session ID on login to prevent fixation attacks. Additionally, the session store is configured to use a secure, in-memory store (connect-redis) for production deployments, ensuring that session data is not vulnerable to theft or tampering.

### 2FA

Two-factor authentication (2FA) is implemented using the TOTP algorithm, with backup codes provided for account recovery. The `speakeasy` library is used for TOTP generation and verification, and the `qrcode` library is used to generate QR codes for easy setup in authenticator apps. During login, the user is prompted for both their password and the TOTP code from their authenticator app. The TOTP secret is securely stored and never transmitted to the client.

### Static File Protection

Static file protection is enforced by restricting access to authenticated users only. The middleware checks if the user is authenticated before serving any static files. This prevents unauthorized access to sensitive files or directories that may be exposed in the `public` folder.

### Input Validation

Input validation and sanitization are performed on all user inputs, including query parameters, request bodies, and headers. The `express-validator` middleware is used to define and enforce validation rules for each input field. This helps prevent common web vulnerabilities such as SQL injection, XSS, and command injection. All user inputs are treated as untrusted and are properly escaped or sanitized before use.

## AI Integration
- Ollama LLM API for natural language analysis of logs/events
- Local inference (no data leaves your server)
- Chat UI with minimize/maximize, sticky open, and animated feedback
- AI summary included in PDF reports

## PDF & Data Export
- Generate PDF reports with your logo and custom header
- Export alerts as CSV or JSON
- Download directly from the dashboard
- PDF includes AI-generated summary and all alert details

## Customization & Branding
- Replace the logo in `server/Apex.png` for PDF reports
- Update UI colors and branding in `public/css/styles.css`
- Modify dashboard title and sections in `public/index.html`

## API Endpoints
- `/api/csrf-token` — Get CSRF token
- `/api/alerts/export-csv` — Export alerts as CSV
- `/api/alerts/export-json` — Export alerts as JSON
- `/api/reports/pdf` — Generate PDF report
- `/api/ollama/chat` — AI chat endpoint (proxied to local Ollama LLM for secure, local-only communication)
- `/api/2fa/*` — 2FA setup/verify endpoints
- `/auth/login` — User login
- `/api/ipwhois/:ip` — Proxy endpoint for IP geolocation lookup (fetches data from ipwho.is and returns it to the frontend securely)

## Scripts & Utilities
- `server/scripts/createAdmin.js` — Create an admin user
- `server/scripts/addUser.js` — Add a new user
- `server/scripts/testDb.js` — Test database connection
- `server/scripts/testRateLimit.js` — Test rate limiting
- **Kali Attack Scripts:** Automated scripts for SQL Injection, Command Injection, Port Scan, XSS, and DDoS (not included in repo, but referenced for demonstration)

## Suricata Custom Rules
- Custom detection rules created for Suricata to identify the five automated attack types.
- Rules are tuned for DVWA and typical web attack patterns.
- Alerts are parsed and visualized in real time in the dashboard.

## Reliability & Monitoring
- SSH reconnection logic ensures data flow even if the VM connection drops.
- All alerts are stored in a dedicated database table, separate from user data.
- Server status (load, storage, uptime) is monitored and displayed.

## Troubleshooting
- Check server logs for errors
- Ensure all environment variables are set
- Verify Suricata and Apache are running and accessible
- For AI chat, ensure Ollama is running on `localhost:11434`
- Ensure SSH connectivity to the Linux Mint VM

## Middleware

- **Authentication Middleware:** Ensures only authenticated users can access protected routes and static files.
- **2FA Middleware:** Handles setup, verification, and rate limiting for two-factor authentication.
- **Security Middleware:** Applies Content Security Policy (CSP), security headers, and other best practices.
- **Rate Limiting Middleware:** Limits requests to sensitive endpoints (login, 2FA) to prevent brute-force attacks.
- **CSRF Middleware:** Protects against cross-site request forgery using tokens.
- **Session Middleware:** Manages secure sessions and cookies for user authentication.
- **Static File Protection:** Restricts access to static files for authenticated users only.

## Contributing
This project is part of a final year engineering and CS license. Contributions are welcome for learning and improvement purposes.

## Third-Party Licenses

This project integrates several open source and third-party components. Their respective licenses are summarized below:

- **Suricata** — GPLv2 (https://suricata.io/)
- **Apache HTTP Server** — Apache License 2.0 (https://httpd.apache.org/)
- **Ollama** — Apache License 2.0 (https://github.com/jmorganca/ollama)
- **Node.js** — MIT License (https://nodejs.org/)
- **Chart.js, chartjs-adapter-moment, cookie-parser, csurf, dotenv, express, express-rate-limit, express-session, express-validator, geoip-lite, heatmap.js, helmet, moment, mysql2, node-fetch, node-telegram-bot-api, pdfkit, qrcode, speakeasy, ssh2, ws, bcrypt, crypto-js, nodemon** — MIT License
- **Leaflet** — BSD 2-Clause License (https://leafletjs.com/)
- **Carto Basemaps for Leaflet** — Creative Commons Attribution 4.0 International (CC BY 4.0) (https://carto.com/attributions)
- **ipwho.is API** — Free public API, attribution required (https://ipwho.is/)
---

**Author:** Grecu Constantin-Liviu-Florin

**Project for:** Final Year License in Technologies and Telecommunications Systems

---
