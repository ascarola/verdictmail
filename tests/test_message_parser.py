"""
test_message_parser.py — Offline unit tests for message_parser.py.

Run from the project root:
    PYTHONPATH=src python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import textwrap
import unittest

from mailsentinel.message_parser import parse_raw_message


# ---------------------------------------------------------------------------
# Sample raw emails
# ---------------------------------------------------------------------------

SIMPLE_PLAIN_EMAIL = textwrap.dedent("""\
    Message-ID: <test001@example.com>
    Date: Fri, 21 Feb 2026 10:00:00 +0000
    From: Legit Sender <sender@example.com>
    To: recipient@gmail.com
    Subject: Hello from example.com
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8
    Received: from mail.example.com (mail.example.com [203.0.113.42])
        by mx.google.com with ESMTP id abc123; Fri, 21 Feb 2026 10:00:00 +0000

    This is a simple test email.
    Visit our site at https://example.com/page?ref=email
    Also check http://bit.ly/shortlink for details.
""").encode("utf-8")


MULTIPART_HTML_EMAIL = textwrap.dedent("""\
    Message-ID: <test002@phishing.example>
    Date: Fri, 21 Feb 2026 11:00:00 +0000
    From: "PayPal Support" <support@totally-not-paypal.xyz>
    To: victim@gmail.com
    Subject: Urgent: Your account has been suspended
    MIME-Version: 1.0
    Content-Type: multipart/alternative; boundary="boundary42"
    Received: from smtp.totally-not-paypal.xyz (smtp.totally-not-paypal.xyz [198.51.100.7])
        by mx.google.com with ESMTP; Fri, 21 Feb 2026 11:00:00 +0000

    --boundary42
    Content-Type: text/plain; charset=utf-8

    Click here to restore your account: http://bit.ly/paypal-fake

    --boundary42
    Content-Type: text/html; charset=utf-8

    <html><body>
    <p>Click <a href="https://evil.example.com/login?steal=1">here</a> to restore your account.</p>
    <p>Or visit <a href="http://tinyurl.com/phish123">our support page</a>.</p>
    </body></html>

    --boundary42--
""").encode("utf-8")


NO_FROM_EMAIL = textwrap.dedent("""\
    Message-ID: <test003@broken.example>
    Date: Fri, 21 Feb 2026 12:00:00 +0000
    Subject: No From Header
    Content-Type: text/plain; charset=utf-8

    Body with no From header.
""").encode("utf-8")


DISPLAY_NAME_SPOOF_EMAIL = textwrap.dedent("""\
    Message-ID: <test004@spoof.example>
    Date: Fri, 21 Feb 2026 13:00:00 +0000
    From: "support@paypal.com" <attacker@malicious-domain.ru>
    To: victim@gmail.com
    Subject: Verify your PayPal account
    Content-Type: text/plain; charset=utf-8
    Received: from mail.malicious-domain.ru (mail.malicious-domain.ru [45.33.32.156])
        by mx.google.com; Fri, 21 Feb 2026 13:00:00 +0000

    Please verify your PayPal account immediately.
""").encode("utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseSimplePlainEmail(unittest.TestCase):
    def setUp(self):
        self.msg = parse_raw_message(SIMPLE_PLAIN_EMAIL)

    def test_message_id(self):
        self.assertEqual(self.msg.message_id, "<test001@example.com>")

    def test_sender_address(self):
        self.assertEqual(self.msg.sender_address, "sender@example.com")

    def test_sender_domain(self):
        self.assertEqual(self.msg.sender_domain, "example.com")

    def test_display_name(self):
        self.assertEqual(self.msg.display_name, "Legit Sender")

    def test_subject(self):
        self.assertEqual(self.msg.subject, "Hello from example.com")

    def test_body_text_nonempty(self):
        self.assertIn("simple test email", self.msg.body_text)

    def test_urls_extracted(self):
        self.assertTrue(any("example.com/page" in u for u in self.msg.urls))

    def test_shortener_url_present(self):
        self.assertTrue(any("bit.ly" in u for u in self.msg.urls))

    def test_originating_ip(self):
        # 203.0.113.42 is a public TEST-NET-3 address, should be extracted
        self.assertEqual(self.msg.originating_ip, "203.0.113.42")

    def test_urls_deduplicated(self):
        self.assertEqual(len(self.msg.urls), len(set(self.msg.urls)))


class TestParseMultipartHtmlEmail(unittest.TestCase):
    def setUp(self):
        self.msg = parse_raw_message(MULTIPART_HTML_EMAIL)

    def test_sender_domain(self):
        self.assertEqual(self.msg.sender_domain, "totally-not-paypal.xyz")

    def test_display_name(self):
        self.assertEqual(self.msg.display_name, "PayPal Support")

    def test_html_anchor_urls_extracted(self):
        url_str = " ".join(self.msg.urls)
        self.assertIn("evil.example.com", url_str)
        self.assertIn("tinyurl.com", url_str)

    def test_plain_text_url_extracted(self):
        self.assertTrue(any("bit.ly" in u for u in self.msg.urls))

    def test_originating_ip_extracted(self):
        self.assertEqual(self.msg.originating_ip, "198.51.100.7")


class TestParseNoFromHeader(unittest.TestCase):
    def setUp(self):
        self.msg = parse_raw_message(NO_FROM_EMAIL)

    def test_sender_address_empty(self):
        self.assertEqual(self.msg.sender_address, "")

    def test_sender_domain_empty(self):
        self.assertEqual(self.msg.sender_domain, "")

    def test_no_originating_ip(self):
        self.assertIsNone(self.msg.originating_ip)


class TestDisplayNameSpoofEmail(unittest.TestCase):
    def setUp(self):
        self.msg = parse_raw_message(DISPLAY_NAME_SPOOF_EMAIL)

    def test_sender_domain_is_attacker(self):
        self.assertEqual(self.msg.sender_domain, "malicious-domain.ru")

    def test_display_name_contains_paypal(self):
        self.assertIn("paypal.com", self.msg.display_name.lower())

    def test_originating_ip(self):
        self.assertEqual(self.msg.originating_ip, "45.33.32.156")


class TestUrlDeduplication(unittest.TestCase):
    def test_no_duplicate_urls(self):
        # Email with the same URL in both plain text and HTML
        raw = textwrap.dedent("""\
            Message-ID: <dedup@test.com>
            From: sender@test.com
            Content-Type: multipart/alternative; boundary="b"

            --b
            Content-Type: text/plain

            Visit https://example.com/same

            --b
            Content-Type: text/html

            <a href="https://example.com/same">click</a>

            --b--
        """).encode("utf-8")
        msg = parse_raw_message(raw)
        urls = msg.urls
        self.assertEqual(len(urls), len(set(urls)), "Duplicate URLs found")


if __name__ == "__main__":
    unittest.main()
