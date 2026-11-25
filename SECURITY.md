# Supply Chain Sentinel — Security Policy & Controls
**Security Framework:** ISO/IEC 27001, SOC 2 Type II Alignment, OWASP ASVS v4.0  
**Status:** Active Enterprise Security Baseline  

---

## 1. Vulnerability Disclosure Policy

Supply Chain Sentinel takes its own software supply chain and application security with paramount seriousness. If you discover a security vulnerability within the platform:

1. **Email:** Report findings to `security@sentinel.defense.org`.
2. **PGP Encryption:** Encrypt your advisory with our operational PGP key (Fingerprint: `A93B 4821 C649 EF81 2984 B731 991F E200 4481`).
3. **Response SLA:** The Sentinel Security Response Team commits to:
   - Initial acknowledgement within 8 hours.
   - Severity triage within 24 hours.
   - Patch release or mitigation guidance within 72 hours for Critical/High issues.
4. **Coordinated Disclosure:** We adhere to standard 90-day responsible disclosure timelines.

---

## 2. Core Platform Security Controls

### 2.1 Cryptographic Standards
- **Password Storage:** Passwords hashed using Argon2id (`t=3, m=65536, p=4`) or bcrypt (work factor 12).
- **Session Tokens:** Stateless JWT with cryptographic signing (RS256 or HMAC-SHA256 with 256-bit entropy secrets). Expiration enforced at 8 hours max; refresh tokens stored securely in HTTP-only, SameSite=Strict cookies.
- **Data in Transit:** TLS 1.3 mandated for all ingress API calls and outbound threat intelligence integrations. Weak ciphers deprecated.

### 2.2 Input Validation & Defensive Coding
- **Strict Pydantic Models:** All incoming request bodies strictly validated against type-enforced schemas; unknown fields rejected (`extra = 'forbid'`).
- **Defensive File Handling:** Ingested files (SBOMs) validated for:
  - MIME type verification.
  - Maximum size restriction (25MB default).
  - Malicious entity rejection via `defusedxml`.
- **SQL Injection Prevention:** 100% parameterized queries via SQLAlchemy 2.0 ORM; raw string concatenation strictly prohibited.
- **Cross-Site Scripting (XSS):** All dynamic strings sanitized and escaped via React JSX; strict Content Security Policy (CSP) headers applied.

### 2.3 API Security & Anti-Abuse
- **Security Headers:**
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Content-Security-Policy: default-src 'self'; connect-src 'self' https://api.osv.dev https://services.nvd.nist.gov; style-src 'self' 'unsafe-inline'`
- **Rate Limiting:** IP-based and user-token-based sliding window rate limits on sensitive endpoints (`/auth/login`, `/sbom/upload`, `/ai/chat`).

---

## 3. Defense Against Supply Chain Attacks on Sentinel

- **Zero Run-Time Dependency Execution:** Ingested code packages are never imported, compiled, or executed on the host.
- **Dependency Pinning:** Backend Python requirements and frontend npm packages are pinned to exact versions with SHA-256 integrity hashes (`package-lock.json`, `requirements.txt`).
- **Automated Self-Audits:** Automated CI/CD runs OSV and safety scanners against Sentinel's own dependencies prior to artifact distribution.
