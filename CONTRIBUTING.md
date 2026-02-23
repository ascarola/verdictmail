# Contributing to VerdictMail

Thank you for your interest in VerdictMail. This document covers how to set up 
a development environment, report bugs, and submit changes.

---

## About the Project

VerdictMail is a homelab-grade, self-hosted Gmail threat analysis daemon. It is 
intentionally lightweight and opinionated — designed to run on a single Ubuntu 
LXC container or bare-metal host with minimal dependencies. Contributions that 
preserve that simplicity are most welcome.

---

## Development Setup

### 1. Fork and clone
```bash
git clone https://github.com/<your-username>/verdictmail.git /opt/verdictmail
cd /opt/verdictmail
```

### 2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Run the test suite
```bash
PYTHONPATH=src python -m pytest tests/ -v
```

All tests should pass before you submit a pull request.

---

## Reporting Bugs

Open a [GitHub Issue](https://github.com/ascarola/verdictmail/issues) and include:

- Operating system and Python version
- AI provider in use (`openai`, `anthropic`, or `ollama`)
- Relevant output from `journalctl -u verdictmail -n 50`
- Contents of `verdictmail.yaml` with any credentials removed
- Steps to reproduce the issue

---

## Submitting Changes

1. Fork the repository and create a branch from `main`:
```bash
   git checkout -b fix/your-fix-description
```

2. Make your changes. Keep each pull request focused on a single concern.

3. Add or update tests if your change affects pipeline behavior.

4. Run the test suite and confirm it passes.

5. Commit with a clear message following this convention:
```
   fix: correct DNSBL timeout handling
   feat: add VirusTotal URL enrichment signal
   docs: clarify App Password setup in README
   chore: update dependencies
```

6. Open a pull request against `main` with a clear description of what 
   changed and why.

---

## What We Welcome

- Bug fixes
- New enrichment signals (additional DNSBL lists, header analysis, etc.)
- Additional AI provider support
- Improved test coverage
- Documentation improvements and clarifications
- Performance improvements to the pipeline

## Please Discuss First

Open an issue before starting work on:

- Large architectural changes to the pipeline
- New external dependencies
- Changes to the audit log schema
- Anything that affects the systemd service behavior or installation layout

This avoids duplicate effort and ensures the change fits the project's direction.

---

## Code Style

- Python, PEP 8
- Prefer clarity over cleverness
- No new dependencies without discussion
- Keep the pipeline stages loosely coupled and independently testable

---

## License

By contributing, you agree that your contributions will be licensed under the 
[MIT License](LICENSE).
