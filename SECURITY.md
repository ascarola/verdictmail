# Security Policy

## Supported Versions

VerdictMail is currently in beta. Only the latest release receives security updates.

| Version | Supported |
|---------|-----------|
| 0.2.x (latest) | ✅ |
| < 0.2.0 | ❌ |

## Reporting a Vulnerability

VerdictMail handles live email data, AI provider credentials, and Gmail 
authentication tokens — so responsible disclosure of security issues is 
important and appreciated.

**Please do not report security vulnerabilities via GitHub Issues.**

Instead, report vulnerabilities using GitHub's private security advisory 
feature:
👉 https://github.com/ascarola/verdictmail/security/advisories/new

Alternatively, you may email the maintainer directly at the address listed 
in the GitHub profile.

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept
- The version of VerdictMail affected
- Any suggested remediation if you have one

### What to expect

- Acknowledgement within 72 hours
- A status update within 7 days indicating whether the issue is accepted 
  or declined
- If accepted: a fix will be prioritized and a patched release issued as 
  soon as practical, with credit given to the reporter in the release notes 
  unless anonymity is requested

### Known security considerations

The following are documented design limitations, not vulnerabilities:

- The web UI runs on plain HTTP (port 80) with no TLS. Do not expose it
  directly to the internet. Use a VPN or reverse proxy with TLS for remote
  access.
- The `/login` route is rate-limited to 10 attempts per minute and 30 per
  hour per IP address (HTTP 429 on breach). This provides brute-force
  resistance on a trusted LAN but is not a substitute for TLS or VPN if
  the UI is exposed beyond localhost.
- Gmail App Passwords are stored in `.env` with 600 permissions. Protect
  access to the host accordingly.
- AI provider API keys are stored in `.env`. Treat this file as a secret.
