"""
test_ai_analyzer.py — Unit tests for ai_analyzer.py.

Run from the project root:
    PYTHONPATH=src python -m pytest tests/ -v

Tests cover:
  - _extract_json:        clean JSON, markdown fences, embedded JSON, invalid input
  - _validate_ai_response: valid input, missing fields, bad threat level, bad confidence,
                           unknown action defaulting to 'pass', case normalisation
  - _build_user_prompt:   key sections present, URLhaus/VirusTotal blocks conditional,
                          DKIM alignment variants, PBL-only note, domain age, body truncation
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import unittest
from types import SimpleNamespace

from verdictmail.ai_analyzer import (
    AiResult,
    _extract_json,
    _validate_ai_response,
    _build_user_prompt,
)
from verdictmail.enrichment import EnrichmentResult, ExpandedUrl


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_parsed(
    sender_address="sender@example.com",
    sender_domain="example.com",
    display_name="Test Sender",
    originating_ip=None,
    body_text="Hello world.",
    body_html="",
    all_headers=None,
):
    """Build a minimal ParsedMessage-compatible namespace for prompt testing."""
    return SimpleNamespace(
        sender_address=sender_address,
        sender_domain=sender_domain,
        display_name=display_name,
        originating_ip=originating_ip,
        body_text=body_text,
        body_html=body_html,
        all_headers=all_headers or {},
    )


def _valid_ai_dict(**overrides):
    """Return a dict that satisfies _validate_ai_response's schema."""
    base = {
        "threat_level": "none",
        "threat_types": [],
        "confidence": 0.1,
        "signals": {},
        "reasoning": "Looks clean.",
        "recommended_action": "pass",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _extract_json
# ---------------------------------------------------------------------------

class TestExtractJson(unittest.TestCase):

    def test_plain_json_object(self):
        raw = '{"threat_level": "none", "confidence": 0.1}'
        result = _extract_json(raw)
        self.assertEqual(result["threat_level"], "none")

    def test_json_fenced_with_language_tag(self):
        raw = '```json\n{"threat_level": "high", "confidence": 0.9}\n```'
        result = _extract_json(raw)
        self.assertEqual(result["threat_level"], "high")

    def test_json_fenced_without_language_tag(self):
        raw = '```\n{"threat_level": "low", "confidence": 0.2}\n```'
        result = _extract_json(raw)
        self.assertEqual(result["threat_level"], "low")

    def test_json_embedded_in_prose(self):
        raw = 'Here is my assessment: {"threat_level": "medium", "confidence": 0.5} as you can see.'
        result = _extract_json(raw)
        self.assertEqual(result["threat_level"], "medium")

    def test_json_with_leading_and_trailing_whitespace(self):
        raw = '   \n  {"threat_level": "none", "confidence": 0.0}  \n  '
        result = _extract_json(raw)
        self.assertEqual(result["confidence"], 0.0)

    def test_nested_json_object(self):
        raw = '{"threat_level": "critical", "signals": {"spf": false, "dkim": true}}'
        result = _extract_json(raw)
        self.assertFalse(result["signals"]["spf"])
        self.assertTrue(result["signals"]["dkim"])

    def test_invalid_json_raises_decode_error(self):
        with self.assertRaises(json.JSONDecodeError):
            _extract_json("this is not json at all")

    def test_empty_string_raises_decode_error(self):
        with self.assertRaises(json.JSONDecodeError):
            _extract_json("")

    def test_only_fence_markers_raises_decode_error(self):
        with self.assertRaises(json.JSONDecodeError):
            _extract_json("```\n```")


# ---------------------------------------------------------------------------
# _validate_ai_response
# ---------------------------------------------------------------------------

class TestValidateAiResponse(unittest.TestCase):

    def test_valid_response_returns_ai_result(self):
        result = _validate_ai_response(_valid_ai_dict())
        self.assertIsInstance(result, AiResult)

    def test_valid_response_fields_are_preserved(self):
        data = _valid_ai_dict(
            threat_level="medium",
            threat_types=["phishing"],
            confidence=0.75,
            signals={"spf": False},
            reasoning="Suspicious domain.",
            recommended_action="flag",
        )
        result = _validate_ai_response(data)
        self.assertEqual(result.threat_level, "medium")
        self.assertEqual(result.threat_types, ["phishing"])
        self.assertAlmostEqual(result.confidence, 0.75)
        self.assertEqual(result.signals, {"spf": False})
        self.assertEqual(result.reasoning, "Suspicious domain.")
        self.assertEqual(result.recommended_action, "flag")

    def test_all_valid_threat_levels_accepted(self):
        for level in ("none", "low", "medium", "high", "critical"):
            with self.subTest(threat_level=level):
                result = _validate_ai_response(_valid_ai_dict(threat_level=level))
                self.assertEqual(result.threat_level, level)

    def test_threat_level_is_lowercased(self):
        result = _validate_ai_response(_valid_ai_dict(threat_level="CRITICAL"))
        self.assertEqual(result.threat_level, "critical")

    def test_invalid_threat_level_raises_value_error(self):
        with self.assertRaises(ValueError):
            _validate_ai_response(_valid_ai_dict(threat_level="extreme"))

    def test_confidence_at_zero_is_valid(self):
        result = _validate_ai_response(_valid_ai_dict(confidence=0.0))
        self.assertAlmostEqual(result.confidence, 0.0)

    def test_confidence_at_one_is_valid(self):
        result = _validate_ai_response(_valid_ai_dict(confidence=1.0))
        self.assertAlmostEqual(result.confidence, 1.0)

    def test_confidence_above_one_raises_value_error(self):
        with self.assertRaises(ValueError):
            _validate_ai_response(_valid_ai_dict(confidence=1.01))

    def test_confidence_below_zero_raises_value_error(self):
        with self.assertRaises(ValueError):
            _validate_ai_response(_valid_ai_dict(confidence=-0.01))

    def test_missing_required_field_raises_value_error(self):
        for field in ("threat_level", "threat_types", "confidence", "signals", "reasoning", "recommended_action"):
            with self.subTest(missing=field):
                data = _valid_ai_dict()
                del data[field]
                with self.assertRaises(ValueError):
                    _validate_ai_response(data)

    def test_all_valid_actions_accepted(self):
        for action in ("pass", "flag", "quarantine", "move_to_junk", "block"):
            with self.subTest(action=action):
                result = _validate_ai_response(_valid_ai_dict(recommended_action=action))
                self.assertEqual(result.recommended_action, action)

    def test_unknown_action_defaults_to_pass(self):
        result = _validate_ai_response(_valid_ai_dict(recommended_action="delete_immediately"))
        self.assertEqual(result.recommended_action, "pass")

    def test_recommended_action_is_lowercased(self):
        result = _validate_ai_response(_valid_ai_dict(recommended_action="FLAG"))
        self.assertEqual(result.recommended_action, "flag")

    def test_raw_response_field_defaults_to_empty_string(self):
        result = _validate_ai_response(_valid_ai_dict())
        self.assertEqual(result.raw_response, "")

    def test_extra_fields_are_ignored(self):
        data = _valid_ai_dict()
        data["extra_field"] = "should be ignored"
        # Should not raise
        result = _validate_ai_response(data)
        self.assertIsInstance(result, AiResult)


# ---------------------------------------------------------------------------
# _build_user_prompt
# ---------------------------------------------------------------------------

class TestBuildUserPrompt(unittest.TestCase):

    def _prompt(self, parsed=None, enrichment=None):
        if parsed is None:
            parsed = _minimal_parsed()
        if enrichment is None:
            enrichment = EnrichmentResult()
        return _build_user_prompt(parsed, enrichment)

    # --- Key sections always present ---

    def test_authentication_section_present(self):
        prompt = self._prompt()
        self.assertIn("--- Authentication Results ---", prompt)

    def test_sender_intelligence_section_present(self):
        prompt = self._prompt()
        self.assertIn("--- Sender Intelligence ---", prompt)

    def test_dnsbl_section_present(self):
        prompt = self._prompt()
        self.assertIn("--- DNSBL ---", prompt)

    def test_urls_section_present(self):
        prompt = self._prompt()
        self.assertIn("--- URLs ---", prompt)

    def test_message_body_section_present(self):
        prompt = self._prompt()
        self.assertIn("--- Message Body ---", prompt)

    def test_sender_address_appears_in_prompt(self):
        parsed = _minimal_parsed(sender_address="attacker@evil.com")
        prompt = self._prompt(parsed=parsed)
        self.assertIn("attacker@evil.com", prompt)

    def test_body_text_appears_in_prompt(self):
        parsed = _minimal_parsed(body_text="Click here to verify your account.")
        prompt = self._prompt(parsed=parsed)
        self.assertIn("Click here to verify your account.", prompt)

    # --- URLhaus block conditional ---

    def test_urlhaus_block_absent_when_no_hits(self):
        enrichment = EnrichmentResult(urlhaus_hits=[])
        prompt = self._prompt(enrichment=enrichment)
        self.assertNotIn("URLhaus", prompt)

    def test_urlhaus_block_present_when_hits_exist(self):
        enrichment = EnrichmentResult(urlhaus_hits=["http://evil.example.com/malware.exe"])
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("URLhaus Threat Intelligence", prompt)
        self.assertIn("http://evil.example.com/malware.exe", prompt)

    def test_urlhaus_block_lists_all_hits(self):
        hits = ["http://a.example.com/bad", "http://b.example.com/worse"]
        enrichment = EnrichmentResult(urlhaus_hits=hits)
        prompt = self._prompt(enrichment=enrichment)
        for hit in hits:
            self.assertIn(hit, prompt)

    # --- VirusTotal block conditional ---

    def test_virustotal_block_absent_when_no_hits(self):
        enrichment = EnrichmentResult(virustotal_hits=[])
        prompt = self._prompt(enrichment=enrichment)
        self.assertNotIn("VirusTotal", prompt)

    def test_virustotal_block_present_when_hits_exist(self):
        enrichment = EnrichmentResult(virustotal_hits=["http://phish.example.com"])
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("VirusTotal Threat Intelligence", prompt)
        self.assertIn("http://phish.example.com", prompt)

    # --- DKIM alignment variants ---

    def test_dkim_alignment_na_when_no_signature(self):
        enrichment = EnrichmentResult(dkim_domain_mismatch=None)
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("N/A (no DKIM-Signature header present)", prompt)

    def test_dkim_alignment_misaligned_when_mismatch_true(self):
        enrichment = EnrichmentResult(
            dkim_domain_mismatch=True,
            dkim_domains=["otherdomain.com"],
        )
        parsed = _minimal_parsed(sender_domain="legit.com")
        prompt = self._prompt(parsed=parsed, enrichment=enrichment)
        self.assertIn("MISALIGNED", prompt)
        self.assertIn("otherdomain.com", prompt)
        self.assertIn("legit.com", prompt)

    def test_dkim_alignment_aligned_when_mismatch_false(self):
        enrichment = EnrichmentResult(
            dkim_domain_mismatch=False,
            dkim_domains=["example.com"],
        )
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("aligned (signing domain(s): example.com)", prompt)

    # --- DNSBL PBL-only note ---

    def test_pbl_only_note_shown_when_pbl_only(self):
        enrichment = EnrichmentResult(
            dnsbl_listed=True,
            dnsbl_pbl_only=True,
            dnsbl_hits=["zen.spamhaus.org"],
        )
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("PBL (Policy Block List) only", prompt)

    def test_pbl_only_note_absent_when_not_listed(self):
        enrichment = EnrichmentResult(dnsbl_listed=False, dnsbl_pbl_only=True)
        prompt = self._prompt(enrichment=enrichment)
        self.assertNotIn("PBL (Policy Block List) only", prompt)

    def test_pbl_only_note_absent_when_not_pbl_only(self):
        enrichment = EnrichmentResult(dnsbl_listed=True, dnsbl_pbl_only=False)
        prompt = self._prompt(enrichment=enrichment)
        self.assertNotIn("PBL (Policy Block List) only", prompt)

    # --- Domain age ---

    def test_domain_age_days_shown_when_set(self):
        enrichment = EnrichmentResult(domain_age_days=5)
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("5", prompt)

    def test_domain_age_days_omitted_when_none(self):
        enrichment = EnrichmentResult(domain_age_days=None)
        prompt = self._prompt(enrichment=enrichment)
        self.assertNotIn("Domain age (days)", prompt)

    # --- Body truncation ---

    def test_long_body_is_truncated(self):
        long_body = "x" * 5000
        parsed = _minimal_parsed(body_text=long_body)
        prompt = self._prompt(parsed=parsed)
        self.assertIn("[...truncated...]", prompt)

    def test_short_body_is_not_truncated(self):
        short_body = "Short message body."
        parsed = _minimal_parsed(body_text=short_body)
        prompt = self._prompt(parsed=parsed)
        self.assertNotIn("[...truncated...]", prompt)

    def test_empty_body_shows_empty_marker(self):
        parsed = _minimal_parsed(body_text="", body_html="")
        prompt = self._prompt(parsed=parsed)
        self.assertIn("(empty)", prompt)

    # --- URL section ---

    def test_urls_section_shows_none_when_no_expanded_urls(self):
        enrichment = EnrichmentResult(expanded_urls=[])
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("(none)", prompt)

    def test_expanded_url_appears_in_prompt(self):
        url = ExpandedUrl(original="http://bit.ly/abc", final="http://real-dest.example.com/page", is_shortener=True)
        enrichment = EnrichmentResult(expanded_urls=[url])
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("http://bit.ly/abc", prompt)
        self.assertIn("http://real-dest.example.com/page", prompt)
        self.assertIn("[SHORTENER]", prompt)

    def test_non_shortener_url_no_shortener_label(self):
        url = ExpandedUrl(original="http://example.com/page", final="http://example.com/page", is_shortener=False)
        enrichment = EnrichmentResult(expanded_urls=[url])
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("http://example.com/page", prompt)
        self.assertNotIn("[SHORTENER]", prompt)

    # --- Authentication values in prompt ---

    def test_spf_valid_true_appears(self):
        enrichment = EnrichmentResult(spf_valid=True)
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("SPF valid:   True", prompt)

    def test_dkim_valid_false_appears(self):
        enrichment = EnrichmentResult(dkim_valid=False)
        prompt = self._prompt(enrichment=enrichment)
        self.assertIn("DKIM valid:  False", prompt)


if __name__ == "__main__":
    unittest.main()
