"""
ai_analyzer.py — Multi-provider AI email threat analysis.

Supported providers:
  - "ollama"     — local Ollama instance (default)
  - "anthropic"  — Anthropic Claude API
  - "openai"     — OpenAI Chat Completions API
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

VALID_THREAT_LEVELS = {"none", "low", "medium", "high", "critical"}
VALID_ACTIONS = {"pass", "flag", "quarantine", "move_to_junk", "block"}


@dataclass
class AiResult:
    threat_level: str
    threat_types: list[str]
    confidence: float
    signals: dict[str, Any]
    reasoning: str
    recommended_action: str
    raw_response: str = ""


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are VerdictMail, an expert email security analyst specialising in
detecting genuinely malicious email. Your job is to protect users from phishing,
credential harvesting, malware delivery, ransomware, and business email compromise (BEC).

IMPORTANT SCOPE — what you are NOT looking for:
- Commercial newsletters, marketing emails, or promotional offers (even aggressive ones)
- Transactional emails from known brands (order confirmations, receipts, booking details,
  shipping notifications, account statements, hotel messages)
- Email from brand subdomains (e.g. eg.expedia.com, em.amazon.com, mail.linkedin.com)
  that authenticate correctly via SPF/DKIM/DMARC — these are NOT spoofing
- Spam (unwanted but harmless mail) — Google/Gmail already filters spam separately

THREAT LEVELS — use these strictly:
- "none"     : No malicious indicators. Legitimate mail, including all commercial/transactional.
- "low"      : Minor anomalies only (e.g. soft-fail SPF with no other signals). Not actionable.
- "medium"   : Moderate concern — suspicious but unconfirmed (e.g. lookalike domain, unknown
               sender with urgent request for action). Warrants human review.
- "high"     : Strong indicators of phishing, credential theft, malware, or BEC.
- "critical" : Near-certain malicious intent (active phishing kit, malware attachment,
               CEO fraud, or confirmed impersonation of a known brand on unrelated domain).

Display-name spoofing: only flag if the sender domain is completely unrelated to the brand
in the display name. A subdomain of the brand (eg.expedia.com for Expedia.com) is legitimate.

You MUST respond with a single valid JSON object matching this exact schema:
{
  "threat_level":       string,  // one of: "none", "low", "medium", "high", "critical"
  "threat_types":       array of strings,  // e.g. ["phishing", "credential_theft"] or []
  "confidence":         number,  // float 0.0–1.0 indicating your certainty in this assessment
  "signals":            object,  // key evidence that informed your decision
  "reasoning":          string,  // concise chain-of-thought explanation (1-3 sentences)
  "recommended_action": string   // one of: "pass", "flag", "quarantine", "move_to_junk", "block"
}

Do not output anything outside the JSON object. Do not add markdown code fences.
"""

# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_user_prompt(parsed_message, enrichment_result) -> str:
    lines: list[str] = ["=== EMAIL ANALYSIS REQUEST ===\n"]

    # Headers
    lines.append("--- Headers ---")
    important_headers = [
        "From", "To", "Subject", "Date", "Reply-To", "Return-Path",
        "X-Mailer", "X-Originating-IP", "MIME-Version", "Content-Type",
        "Received-SPF", "Authentication-Results", "DKIM-Signature",
        "ARC-Authentication-Results",
    ]
    for h in important_headers:
        val = parsed_message.all_headers.get(h, "")
        if val:
            lines.append(f"  {h}: {val}")
    lines.append("")

    # Authentication
    lines.append("--- Authentication Results ---")
    lines.append(f"  SPF valid:   {enrichment_result.spf_valid}")
    lines.append(f"  DKIM valid:  {enrichment_result.dkim_valid}")
    lines.append(f"  DMARC valid: {enrichment_result.dmarc_valid}")
    lines.append("")

    # Sender intelligence
    lines.append("--- Sender Intelligence ---")
    lines.append(f"  Sender address:         {parsed_message.sender_address}")
    lines.append(f"  Sender domain:          {parsed_message.sender_domain}")
    lines.append(f"  Display name:           {parsed_message.display_name!r}")
    lines.append(f"  Display-name spoofing:  {enrichment_result.display_name_spoofing}")
    lines.append(f"  Originating IP:         {parsed_message.originating_ip or 'unknown'}")
    lines.append(f"  New domain (<30 days):  {enrichment_result.new_domain}")
    if enrichment_result.domain_age_days is not None:
        lines.append(f"  Domain age (days):      {enrichment_result.domain_age_days}")
    lines.append("")

    # DNSBL
    lines.append("--- DNSBL ---")
    lines.append(f"  Listed: {enrichment_result.dnsbl_listed}")
    if enrichment_result.dnsbl_hits:
        lines.append(f"  Hits:   {', '.join(enrichment_result.dnsbl_hits)}")
    if enrichment_result.dnsbl_listed and enrichment_result.dnsbl_pbl_only:
        lines.append("  NOTE: All DNSBL hits are PBL (Policy Block List) only.")
        lines.append("        PBL means the ISP designated this as an end-user IP that should")
        lines.append("        use a mail relay rather than send directly. This is NOT evidence")
        lines.append("        of spam or malicious activity and should be treated as a weak signal.")
    lines.append("")

    # URLs
    lines.append("--- URLs ---")
    if enrichment_result.expanded_urls:
        for eu in enrichment_result.expanded_urls[:10]:
            shortener_note = " [SHORTENER]" if eu.is_shortener else ""
            if eu.original != eu.final:
                lines.append(f"  {eu.original}{shortener_note}  →  {eu.final}")
            else:
                lines.append(f"  {eu.original}{shortener_note}")
    else:
        lines.append("  (none)")
    lines.append("")

    # URLhaus
    if enrichment_result.urlhaus_hits:
        lines.append("--- URLhaus Threat Intelligence ---")
        lines.append("  ALERT: One or more URLs in this message match the URLhaus malware URL database.")
        lines.append("  URLhaus is a community-maintained feed of known malware distribution and C2 URLs.")
        lines.append("  A match is a strong indicator of malicious content.")
        for hit in enrichment_result.urlhaus_hits:
            lines.append(f"  Listed: {hit}")
        lines.append("")

    # VirusTotal
    if enrichment_result.virustotal_hits:
        lines.append("--- VirusTotal Threat Intelligence ---")
        lines.append("  ALERT: One or more URLs or IPs in this message were flagged by VirusTotal.")
        lines.append("  VirusTotal aggregates results from 90+ antivirus and security vendors.")
        lines.append("  A match is a strong indicator of malicious or phishing content.")
        for hit in enrichment_result.virustotal_hits:
            lines.append(f"  Flagged: {hit}")
        lines.append("")

    # Body (truncated)
    body = parsed_message.body_text.strip()
    if not body and parsed_message.body_html:
        from bs4 import BeautifulSoup
        body = BeautifulSoup(parsed_message.body_html, "html.parser").get_text(
            separator="\n", strip=True
        )
    if body:
        truncated = body[:4000]
        if len(body) > 4000:
            truncated += "\n[...truncated...]"
        lines.append("--- Message Body ---")
        lines.append(truncated)
    else:
        lines.append("--- Message Body ---")
        lines.append("(empty)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> dict:
    """Extract a JSON object from text that may contain markdown fences or preamble."""
    text = text.strip()
    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    if text.startswith("```"):
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1:]
        if text.endswith("```"):
            text = text[:-3].rstrip()
        text = text.strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back: find the first { ... } block in the text
    import re
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        return json.loads(match.group())
    raise json.JSONDecodeError("No JSON object found in response", text, 0)


def _validate_ai_response(data: dict[str, Any]) -> AiResult:
    """Validate parsed JSON against the required schema and return AiResult."""
    required = {"threat_level", "threat_types", "confidence", "signals", "reasoning", "recommended_action"}
    missing = required - set(data.keys())
    if missing:
        raise ValueError(f"Missing fields in AI response: {missing}")

    threat_level = str(data["threat_level"]).lower()
    if threat_level not in VALID_THREAT_LEVELS:
        raise ValueError(f"Invalid threat_level: {threat_level!r}")

    confidence = float(data["confidence"])
    if not (0.0 <= confidence <= 1.0):
        raise ValueError(f"confidence out of range: {confidence}")

    threat_types = list(data["threat_types"])
    signals = dict(data["signals"])
    reasoning = str(data["reasoning"])
    recommended_action = str(data["recommended_action"]).lower()
    if recommended_action not in VALID_ACTIONS:
        logger.warning("Unknown recommended_action %r — defaulting to 'pass'", recommended_action)
        recommended_action = "pass"

    return AiResult(
        threat_level=threat_level,
        threat_types=threat_types,
        confidence=confidence,
        signals=signals,
        reasoning=reasoning,
        recommended_action=recommended_action,
    )


# ---------------------------------------------------------------------------
# Main analyzer class (multi-provider)
# ---------------------------------------------------------------------------

class AiAnalyzer:
    MAX_RETRIES = 5
    BASE_DELAY = 2.0

    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5-coder:14b",
        timeout_seconds: int = 120,
        base_url: str = "http://localhost:11434",
        api_key: str = "",
        # Legacy compat: if called with positional base_url, model, timeout
        **kwargs,
    ):
        self.provider = provider.lower()
        self.model = model
        self.timeout = timeout_seconds
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.api_key = api_key

    def analyze(self, parsed_message, enrichment_result) -> AiResult:
        """Dispatch to the appropriate provider."""
        if self.provider == "ollama":
            return self._analyze_ollama(parsed_message, enrichment_result)
        elif self.provider == "anthropic":
            return self._analyze_anthropic(parsed_message, enrichment_result)
        elif self.provider == "openai":
            return self._analyze_openai(parsed_message, enrichment_result)
        else:
            raise ValueError(f"Unknown AI provider: {self.provider!r}. Use 'ollama', 'anthropic', or 'openai'.")

    # ------------------------------------------------------------------
    # Ollama
    # ------------------------------------------------------------------

    def _analyze_ollama(self, parsed_message, enrichment_result) -> AiResult:
        user_prompt = _build_user_prompt(parsed_message, enrichment_result)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
        }
        url = f"{self.base_url}/api/chat"
        raw_response = ""
        last_exc: Optional[Exception] = None

        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        for attempt in range(self.MAX_RETRIES):
            delay = self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1)
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, json=payload, headers=headers)
                if resp.status_code != 200:
                    raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}")
                raw_response = resp.text
                data = resp.json()
                content = data["message"]["content"]
                parsed_json = json.loads(content)
                ai_result = _validate_ai_response(parsed_json)
                ai_result.raw_response = raw_response
                logger.info(
                    "AI analysis complete (ollama/%s): threat=%s confidence=%.2f action=%s",
                    self.model, ai_result.threat_level, ai_result.confidence, ai_result.recommended_action,
                )
                return ai_result
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                logger.warning("Ollama connection error (attempt %d/%d): %s — retrying in %.1fs",
                               attempt + 1, self.MAX_RETRIES, exc, delay)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                last_exc = exc
                logger.warning("AI response parse/validation error (attempt %d/%d): %s — retrying in %.1fs",
                               attempt + 1, self.MAX_RETRIES, exc, delay)
            except RuntimeError as exc:
                last_exc = exc
                logger.warning("Ollama error (attempt %d/%d): %s — retrying in %.1fs",
                               attempt + 1, self.MAX_RETRIES, exc, delay)
            except Exception as exc:
                last_exc = exc
                logger.error("Unexpected AI error (attempt %d/%d): %s", attempt + 1, self.MAX_RETRIES, exc)
            if attempt < self.MAX_RETRIES - 1:
                time.sleep(delay)

        raise RuntimeError(f"AI analysis failed after {self.MAX_RETRIES} attempts. Last error: {last_exc}")

    # ------------------------------------------------------------------
    # Anthropic
    # ------------------------------------------------------------------

    def _analyze_anthropic(self, parsed_message, enrichment_result) -> AiResult:
        try:
            import anthropic as anthropic_sdk
        except ImportError:
            raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

        user_prompt = _build_user_prompt(parsed_message, enrichment_result)
        client = anthropic_sdk.Anthropic(api_key=self.api_key, timeout=self.timeout)
        last_exc: Optional[Exception] = None

        for attempt in range(self.MAX_RETRIES):
            delay = self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1)
            try:
                message = client.messages.create(
                    model=self.model,
                    max_tokens=1024,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                    temperature=0.1,
                )
                content = message.content[0].text
                logger.debug("Anthropic raw response: %r", content[:500])
                parsed_json = _extract_json(content)
                ai_result = _validate_ai_response(parsed_json)
                ai_result.raw_response = content
                logger.info(
                    "AI analysis complete (anthropic/%s): threat=%s confidence=%.2f action=%s",
                    self.model, ai_result.threat_level, ai_result.confidence, ai_result.recommended_action,
                )
                return ai_result
            except (json.JSONDecodeError, ValueError) as exc:
                last_exc = exc
                logger.warning("Anthropic response parse/validation error (attempt %d/%d): %s — retrying in %.1fs",
                               attempt + 1, self.MAX_RETRIES, exc, delay)
            except Exception as exc:
                last_exc = exc
                # Check for rate limit or connection errors
                exc_str = str(exc).lower()
                if any(k in exc_str for k in ("rate limit", "timeout", "connection", "overload")):
                    logger.warning("Anthropic transient error (attempt %d/%d): %s — retrying in %.1fs",
                                   attempt + 1, self.MAX_RETRIES, exc, delay)
                else:
                    logger.error("Anthropic error (attempt %d/%d): %s", attempt + 1, self.MAX_RETRIES, exc)
                    raise  # Non-transient — don't retry
            if attempt < self.MAX_RETRIES - 1:
                time.sleep(delay)

        raise RuntimeError(f"AI analysis failed after {self.MAX_RETRIES} attempts. Last error: {last_exc}")

    # ------------------------------------------------------------------
    # OpenAI
    # ------------------------------------------------------------------

    def _analyze_openai(self, parsed_message, enrichment_result) -> AiResult:
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError("openai package not installed. Run: pip install openai")

        user_prompt = _build_user_prompt(parsed_message, enrichment_result)
        client = OpenAI(api_key=self.api_key, timeout=self.timeout)
        last_exc: Optional[Exception] = None

        for attempt in range(self.MAX_RETRIES):
            delay = self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1)
            try:
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                )
                content = response.choices[0].message.content
                parsed_json = json.loads(content)
                ai_result = _validate_ai_response(parsed_json)
                ai_result.raw_response = content
                logger.info(
                    "AI analysis complete (openai/%s): threat=%s confidence=%.2f action=%s",
                    self.model, ai_result.threat_level, ai_result.confidence, ai_result.recommended_action,
                )
                return ai_result
            except (json.JSONDecodeError, ValueError) as exc:
                last_exc = exc
                logger.warning("OpenAI response parse/validation error (attempt %d/%d): %s — retrying in %.1fs",
                               attempt + 1, self.MAX_RETRIES, exc, delay)
            except Exception as exc:
                last_exc = exc
                exc_str = str(exc).lower()
                if any(k in exc_str for k in ("rate limit", "timeout", "connection", "overload")):
                    logger.warning("OpenAI transient error (attempt %d/%d): %s — retrying in %.1fs",
                                   attempt + 1, self.MAX_RETRIES, exc, delay)
                else:
                    logger.error("OpenAI error (attempt %d/%d): %s", attempt + 1, self.MAX_RETRIES, exc)
                    raise
            if attempt < self.MAX_RETRIES - 1:
                time.sleep(delay)

        raise RuntimeError(f"AI analysis failed after {self.MAX_RETRIES} attempts. Last error: {last_exc}")
