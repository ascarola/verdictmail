"""
enrichment.py — SPF/DMARC, DKIM, DNSBL, WHOIS, display-name spoofing,
and URL expansion enrichment pipeline.
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import dns.resolver
import requests
import whois

logger = logging.getLogger(__name__)

# Common URL shortener domains
_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "bc.vc", "clk.sh", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in",
})

_DOMAIN_IN_NAME_RE = re.compile(
    r"\b([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})\b"
)

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
_VT_URL_API  = "https://www.virustotal.com/api/v3/urls/{}"
_VT_IP_API   = "https://www.virustotal.com/api/v3/ip_addresses/{}"


@dataclass
class ExpandedUrl:
    original: str
    final: str
    is_shortener: bool


@dataclass
class EnrichmentResult:
    spf_valid: bool = False
    dmarc_valid: bool = False
    dkim_valid: bool = False
    display_name_spoofing: bool = False
    new_domain: bool = False
    domain_age_days: Optional[int] = None
    dnsbl_listed: bool = False
    dnsbl_pbl_only: bool = False   # True if every hit is PBL (ISP policy) with no SBL/XBL
    dnsbl_hits: list[str] = field(default_factory=list)
    expanded_urls: list[ExpandedUrl] = field(default_factory=list)
    urlhaus_checked: bool = False   # True if the API key was present and check ran
    urlhaus_hits: list[str] = field(default_factory=list)
    virustotal_checked: bool = False  # True if the API key was present and check ran
    virustotal_hits: list[str] = field(default_factory=list)
    error_notes: list[str] = field(default_factory=list)


class EnrichmentPipeline:
    def __init__(self, dnsbl_lists: list[str]):
        self.dnsbl_lists = dnsbl_lists

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, raw_bytes: bytes, parsed_message) -> EnrichmentResult:
        """Run all enrichment checks and return an EnrichmentResult."""
        result = EnrichmentResult()

        sender_domain = parsed_message.sender_domain
        display_name = parsed_message.display_name
        originating_ip = parsed_message.originating_ip

        # SPF / DMARC
        if sender_domain:
            self._check_spf_dmarc(sender_domain, result)

        # DKIM
        self._check_dkim(raw_bytes, result)

        # Display-name spoofing
        if sender_domain and display_name:
            result.display_name_spoofing = self._check_display_name_spoofing(
                display_name, sender_domain
            )

        # Domain age
        if sender_domain:
            self._check_domain_age(sender_domain, result)

        # DNSBL
        if originating_ip:
            self._check_dnsbl(originating_ip, result)

        # URL expansion (first 10 only)
        urls_to_expand = parsed_message.urls[:10]
        self._expand_urls(urls_to_expand, result)

        # URLhaus threat intelligence (uses final URLs from expansion)
        self._check_urlhaus(result)

        # VirusTotal URL + IP reputation
        self._check_virustotal(result, originating_ip)

        return result

    # ------------------------------------------------------------------
    # SPF / DMARC via checkdmarc
    # ------------------------------------------------------------------

    def _check_spf_dmarc(self, domain: str, result: EnrichmentResult) -> None:
        try:
            import checkdmarc
            report = checkdmarc.check_domains([domain])
            # check_domains returns a list when given a list
            if isinstance(report, list):
                report = report[0] if report else {}

            spf_data = report.get("spf", {})
            dmarc_data = report.get("dmarc", {})

            result.spf_valid = bool(spf_data.get("valid", False))
            result.dmarc_valid = bool(dmarc_data.get("valid", False))

            logger.debug(
                "SPF=%s DMARC=%s for domain %s",
                result.spf_valid,
                result.dmarc_valid,
                domain,
            )
        except Exception as exc:
            note = f"checkdmarc error for {domain}: {exc}"
            logger.warning(note)
            result.error_notes.append(note)

    # ------------------------------------------------------------------
    # DKIM via dkimpy
    # ------------------------------------------------------------------

    def _check_dkim(self, raw_bytes: bytes, result: EnrichmentResult) -> None:
        try:
            import dkim
            result.dkim_valid = dkim.verify(raw_bytes)
            logger.debug("DKIM valid=%s", result.dkim_valid)
        except Exception as exc:
            note = f"DKIM verification error: {exc}"
            logger.debug(note)
            result.error_notes.append(note)
            result.dkim_valid = False

    # ------------------------------------------------------------------
    # Display-name spoofing
    # ------------------------------------------------------------------

    def _check_display_name_spoofing(
        self, display_name: str, sender_domain: str
    ) -> bool:
        """
        Flag if the display name contains a domain that is unrelated to the
        actual sending domain — classic brand impersonation.

        A sender is considered legitimate if its domain is exactly the
        display-name domain OR a subdomain of it (e.g. 'eg.expedia.com'
        sending on behalf of 'Expedia.com' is not spoofing).
        """
        sender_lower = sender_domain.lower()
        matches = _DOMAIN_IN_NAME_RE.findall(display_name)
        for match in matches:
            match_lower = match.lower()
            # Allow exact match or subdomain of the brand's root domain
            if sender_lower != match_lower and not sender_lower.endswith("." + match_lower):
                logger.info(
                    "Display-name spoofing detected: name contains '%s', sender is '%s'",
                    match_lower,
                    sender_lower,
                )
                return True
        return False

    # ------------------------------------------------------------------
    # Domain age via python-whois
    # ------------------------------------------------------------------

    def _check_domain_age(self, domain: str, result: EnrichmentResult) -> None:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                age_days = (now - creation_date).days
                result.domain_age_days = age_days
                result.new_domain = age_days < 30
                logger.debug(
                    "Domain %s age=%d days new=%s", domain, age_days, result.new_domain
                )
        except Exception as exc:
            note = f"WHOIS error for {domain}: {exc}"
            logger.debug(note)
            result.error_notes.append(note)

    # ------------------------------------------------------------------
    # DNSBL
    # ------------------------------------------------------------------

    def _check_dnsbl(self, ip: str, result: EnrichmentResult) -> None:
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
        except Exception:
            return

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 3.0

        # Spamhaus return codes: 127.0.0.2-3=SBL, 127.0.0.4-7=XBL, 127.0.0.10-11=PBL
        # PBL = ISP policy (end-user netblock should use relay), NOT a spam/malware listing
        _PBL_CODES = {"127.0.0.10", "127.0.0.11"}

        sbl_xbl_hits: list[str] = []
        pbl_hits: list[str] = []

        for dnsbl in self.dnsbl_lists:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                answers = resolver.resolve(query, "A")
                return_codes = [str(r) for r in answers]
                is_pbl = all(code in _PBL_CODES for code in return_codes)
                if is_pbl:
                    pbl_hits.append(dnsbl)
                    logger.info("IP %s listed on DNSBL %s (PBL — ISP policy only)", ip, dnsbl)
                else:
                    sbl_xbl_hits.append(dnsbl)
                    logger.info("IP %s listed on DNSBL %s (SBL/XBL codes: %s)", ip, dnsbl, return_codes)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # not listed
            except Exception as exc:
                logger.debug("DNSBL %s lookup error for %s: %s", dnsbl, ip, exc)

        if sbl_xbl_hits or pbl_hits:
            result.dnsbl_listed = True
            result.dnsbl_hits = [f"{h} (SBL/XBL)" for h in sbl_xbl_hits] + \
                                 [f"{h} (PBL)" for h in pbl_hits]
            result.dnsbl_pbl_only = len(sbl_xbl_hits) == 0

    # ------------------------------------------------------------------
    # URL expansion
    # ------------------------------------------------------------------

    def _expand_urls(self, urls: list[str], result: EnrichmentResult) -> None:
        session = requests.Session()
        session.max_redirects = 10
        headers = {"User-Agent": "VerdictMail/1.0"}

        for url in urls:
            parsed = urlparse(url)
            is_shortener = parsed.netloc.lower().lstrip("www.") in _SHORTENER_DOMAINS

            final_url = url  # default: no outbound request

            if is_shortener:
                # Only follow redirects for known shortener domains — never
                # fetch arbitrary URLs from email bodies (prevents beaconing
                # to malicious infrastructure).
                try:
                    resp = session.head(
                        url,
                        allow_redirects=True,
                        timeout=5,
                        headers=headers,
                        verify=True,
                    )
                    final_url = resp.url
                except Exception:
                    # Fall back to GET if HEAD not supported
                    try:
                        resp = session.get(
                            url,
                            allow_redirects=True,
                            timeout=5,
                            headers=headers,
                            stream=True,
                            verify=True,
                        )
                        final_url = resp.url
                        resp.close()
                    except Exception as exc:
                        logger.debug("URL expansion failed for %s: %s", url, exc)
            else:
                logger.debug("Skipping live fetch for non-shortener URL: %s", url)

            result.expanded_urls.append(
                ExpandedUrl(original=url, final=final_url, is_shortener=is_shortener)
            )

    # ------------------------------------------------------------------
    # URLhaus threat intelligence
    # ------------------------------------------------------------------

    def _check_urlhaus(self, result: EnrichmentResult) -> None:
        """Look up each URL (using its final destination) against the URLhaus
        malware URL database. Passive — no connection to the URL itself.
        Requires URLHAUS_API_KEY in the environment; skips silently if absent."""
        import os
        api_key = os.environ.get("URLHAUS_API_KEY", "").strip()
        if not api_key:
            logger.debug("URLhaus lookup skipped: URLHAUS_API_KEY not configured")
            return

        result.urlhaus_checked = True
        urls_to_check = [
            eu.final for eu in result.expanded_urls
            if urlparse(eu.final).scheme in ("http", "https")
        ]
        for url in urls_to_check:
            try:
                resp = requests.post(
                    _URLHAUS_API,
                    data={"url": url},
                    timeout=5,
                    headers={"User-Agent": "VerdictMail/1.0", "Auth-Key": api_key},
                )
                data = resp.json()
                if data.get("query_status") == "ok":
                    threat = data.get("threat", "unknown")
                    url_status = data.get("url_status", "unknown")
                    result.urlhaus_hits.append(
                        f"{url} (threat={threat}, status={url_status})"
                    )
                    logger.info(
                        "URLhaus hit: %s threat=%s status=%s", url, threat, url_status
                    )
            except Exception as exc:
                logger.debug("URLhaus lookup failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # VirusTotal URL + IP reputation
    # ------------------------------------------------------------------

    def _check_virustotal(self, result: EnrichmentResult, originating_ip: Optional[str]) -> None:
        """Check URLs and sender IP against VirusTotal's reputation database.
        Requires VIRUSTOTAL_API_KEY in the environment; skips silently if absent.
        Checks sender IP (1 request) and up to 2 URLs (2 requests) to stay
        within the free-tier rate limit of 4 requests/minute."""
        import base64
        import os
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            logger.debug("VirusTotal lookup skipped: VIRUSTOTAL_API_KEY not configured")
            return

        result.virustotal_checked = True
        headers = {"x-apikey": api_key, "User-Agent": "VerdictMail/1.0"}

        def _vt_get(url: str) -> dict:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 429:
                logger.debug("VirusTotal rate limit reached — skipping remaining checks")
                return {"_rate_limited": True}
            resp.raise_for_status()
            return resp.json()

        def _stats_to_hit(label: str, stats: dict) -> Optional[str]:
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            if malicious >= 3 or (malicious + suspicious) >= 5:
                return f"{label} (malicious={malicious}/{total}, suspicious={suspicious}/{total})"
            return None

        # --- IP check ---
        if originating_ip:
            try:
                data = _vt_get(_VT_IP_API.format(originating_ip))
                if data.get("_rate_limited"):
                    return
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                hit = _stats_to_hit(f"IP {originating_ip}", stats)
                if hit:
                    result.virustotal_hits.append(hit)
                    logger.info("VirusTotal IP hit: %s", hit)
            except Exception as exc:
                logger.debug("VirusTotal IP lookup failed for %s: %s", originating_ip, exc)

        # --- URL checks (up to 2) ---
        urls_to_check = [
            eu.final for eu in result.expanded_urls
            if urlparse(eu.final).scheme in ("http", "https")
        ][:2]
        for url in urls_to_check:
            try:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                data = _vt_get(_VT_URL_API.format(url_id))
                if data.get("_rate_limited"):
                    return
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                hit = _stats_to_hit(url, stats)
                if hit:
                    result.virustotal_hits.append(hit)
                    logger.info("VirusTotal URL hit: %s", hit)
            except Exception as exc:
                logger.debug("VirusTotal URL lookup failed for %s: %s", url, exc)
