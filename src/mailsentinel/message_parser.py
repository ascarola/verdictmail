"""
message_parser.py — RFC822 email parsing, header/body/URL extraction.
"""

from __future__ import annotations

import email
import logging
import re
from dataclasses import dataclass, field
from email.message import Message
from typing import Optional

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Regex for extracting URLs from plain text
_URL_RE = re.compile(
    r"https?://"
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
    r")",
    re.IGNORECASE,
)

# Common URL shortener domains
_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "bc.vc", "clk.sh", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in",
})


@dataclass
class ParsedMessage:
    message_id: str
    date: str
    from_header: str
    sender_address: str          # bare email address from From
    sender_domain: str           # domain part of sender_address
    display_name: str            # display name from From (may be empty)
    subject: str
    all_headers: dict[str, str]
    originating_ip: Optional[str]
    body_text: str
    body_html: str
    urls: list[str] = field(default_factory=list)


def _extract_address(from_header: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a From header value."""
    from email.utils import parseaddr
    display_name, addr = parseaddr(from_header)
    return display_name.strip(), addr.strip().lower()


def _extract_originating_ip(msg: Message) -> Optional[str]:
    """
    Walk Received headers from last to first (oldest to newest external hop)
    and return the first IPv4/IPv6 address that is not a private/loopback address.
    """
    received_headers: list[str] = msg.get_all("Received") or []
    # Received headers are ordered newest-first in the raw message
    # We want the oldest external hop → iterate in reverse
    ipv4_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    private_re = re.compile(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fe80:)"
    )

    for received in reversed(received_headers):
        for match in ipv4_re.finditer(received):
            ip = match.group(1)
            if not private_re.match(ip):
                return ip
    return None


def _extract_body(msg: Message) -> tuple[str, str]:
    """Return (plain_text, html_text) from a (possibly multipart) message."""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/plain":
                plain_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html_parts.append(text)
                else:
                    plain_parts.append(text)
        except Exception:
            pass

    return "\n".join(plain_parts), "\n".join(html_parts)


def _extract_urls(plain_text: str, html_text: str) -> list[str]:
    """Return a deduplicated list of URLs found in both plain text and HTML."""
    urls: list[str] = []

    # From plain text
    urls.extend(_URL_RE.findall(plain_text))

    # From HTML anchor tags via BeautifulSoup
    if html_text:
        soup = BeautifulSoup(html_text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("http://", "https://")):
                urls.append(href)
        # Also scan raw HTML text for any missed URLs
        urls.extend(_URL_RE.findall(html_text))

    # Deduplicate preserving order
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def parse_raw_message(raw_bytes: bytes) -> ParsedMessage:
    """Parse raw RFC822 bytes and return a ParsedMessage dataclass."""
    msg = email.message_from_bytes(raw_bytes)

    from_header = msg.get("From", "")
    display_name, sender_address = _extract_address(from_header)
    sender_domain = sender_address.split("@")[-1] if "@" in sender_address else ""

    all_headers: dict[str, str] = {}
    for key in msg.keys():
        # Collect last value for duplicate headers (or first occurrence for key headers)
        all_headers[key] = str(msg.get(key, ""))

    originating_ip = _extract_originating_ip(msg)
    body_text, body_html = _extract_body(msg)
    urls = _extract_urls(body_text, body_html)

    parsed = ParsedMessage(
        message_id=msg.get("Message-ID", "").strip(),
        date=msg.get("Date", ""),
        from_header=from_header,
        sender_address=sender_address,
        sender_domain=sender_domain,
        display_name=display_name,
        subject=msg.get("Subject", ""),
        all_headers=all_headers,
        originating_ip=originating_ip,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
    )

    logger.debug(
        "Parsed message %s: from=%s subject=%s urls=%d",
        parsed.message_id,
        parsed.sender_address,
        parsed.subject,
        len(parsed.urls),
    )
    return parsed
