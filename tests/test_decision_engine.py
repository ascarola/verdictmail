"""
test_decision_engine.py — Unit tests for decision_engine.py.

Run from the project root:
    PYTHONPATH=src python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import unittest
from types import SimpleNamespace

from verdictmail.decision_engine import DecisionEngine, FinalAction


def ai(threat_level, confidence, recommended_action="flag"):
    """Build a minimal AI result object for testing."""
    return SimpleNamespace(
        threat_level=threat_level,
        confidence=confidence,
        recommended_action=recommended_action,
    )


class TestDecisionEnginePassRules(unittest.TestCase):
    """Rules that always produce PASS regardless of confidence."""

    def setUp(self):
        self.engine = DecisionEngine(flag_threshold=0.6, junk_threshold=0.8)

    # Rule 1a — threat_level == none
    def test_none_threat_always_passes(self):
        result = self.engine.decide(ai("none", 0.99))
        self.assertEqual(result, FinalAction.PASS)

    def test_none_threat_with_junk_action_still_passes(self):
        result = self.engine.decide(ai("none", 0.99, "move_to_junk"))
        self.assertEqual(result, FinalAction.PASS)

    # Rule 1b — ai_action == pass overrides everything
    def test_pass_action_overrides_high_threat(self):
        result = self.engine.decide(ai("high", 0.99, "pass"))
        self.assertEqual(result, FinalAction.PASS)

    def test_pass_action_overrides_critical_threat(self):
        result = self.engine.decide(ai("critical", 0.99, "pass"))
        self.assertEqual(result, FinalAction.PASS)

    # Rule 2 — threat_level == low always passes
    def test_low_threat_passes_regardless_of_confidence(self):
        for confidence in (0.0, 0.5, 0.8, 0.99):
            with self.subTest(confidence=confidence):
                result = self.engine.decide(ai("low", confidence))
                self.assertEqual(result, FinalAction.PASS)

    def test_low_threat_passes_even_with_aggressive_action(self):
        result = self.engine.decide(ai("low", 0.99, "block"))
        self.assertEqual(result, FinalAction.PASS)


class TestDecisionEngineCritical(unittest.TestCase):
    """Rule 3 — critical threat always junks, ignoring confidence and action."""

    def setUp(self):
        self.engine = DecisionEngine(flag_threshold=0.6, junk_threshold=0.8)

    def test_critical_always_junks(self):
        result = self.engine.decide(ai("critical", 0.5))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_critical_junks_at_zero_confidence(self):
        result = self.engine.decide(ai("critical", 0.0))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_critical_junks_with_flag_action(self):
        result = self.engine.decide(ai("critical", 0.5, "flag"))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)


class TestDecisionEngineHighThreat(unittest.TestCase):
    """Rules 4 and 5 — high threat with confidence and action combinations."""

    def setUp(self):
        self.engine = DecisionEngine(flag_threshold=0.6, junk_threshold=0.8)

    # Rule 4 — high + confidence >= junk_threshold → MOVE_TO_JUNK
    def test_high_above_junk_threshold_junks(self):
        result = self.engine.decide(ai("high", 0.80))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_high_well_above_junk_threshold_junks(self):
        result = self.engine.decide(ai("high", 0.99))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_high_at_exact_junk_threshold_junks(self):
        result = self.engine.decide(ai("high", 0.80))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_high_just_below_junk_threshold_does_not_junk_via_rule4(self):
        # Rule 4 won't fire but Rule 5 or 6 might depending on action
        result = self.engine.decide(ai("high", 0.79, "flag"))
        # Should FLAG (Rule 6) not MOVE_TO_JUNK (Rule 4)
        self.assertEqual(result, FinalAction.FLAG)

    # Rule 5 — high + aggressive action + confidence >= flag_threshold → MOVE_TO_JUNK
    def test_high_aggressive_action_above_flag_threshold_junks(self):
        for action in ("quarantine", "move_to_junk", "block"):
            with self.subTest(action=action):
                result = self.engine.decide(ai("high", 0.70, action))
                self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_high_aggressive_action_below_flag_threshold_passes(self):
        result = self.engine.decide(ai("high", 0.50, "block"))
        self.assertEqual(result, FinalAction.PASS)

    def test_high_non_aggressive_action_below_junk_threshold_flags(self):
        # Rule 5 requires aggressive action; "flag" is not aggressive
        result = self.engine.decide(ai("high", 0.70, "flag"))
        self.assertEqual(result, FinalAction.FLAG)

    def test_high_at_exact_flag_threshold_with_aggressive_action_junks(self):
        result = self.engine.decide(ai("high", 0.60, "block"))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_high_just_below_flag_threshold_with_aggressive_action_passes(self):
        result = self.engine.decide(ai("high", 0.59, "block"))
        self.assertEqual(result, FinalAction.PASS)


class TestDecisionEngineMediumThreat(unittest.TestCase):
    """Rule 6 — medium threat flags when confidence meets threshold."""

    def setUp(self):
        self.engine = DecisionEngine(flag_threshold=0.6, junk_threshold=0.8)

    def test_medium_above_flag_threshold_flags(self):
        result = self.engine.decide(ai("medium", 0.70))
        self.assertEqual(result, FinalAction.FLAG)

    def test_medium_at_exact_flag_threshold_flags(self):
        result = self.engine.decide(ai("medium", 0.60))
        self.assertEqual(result, FinalAction.FLAG)

    def test_medium_just_below_flag_threshold_passes(self):
        result = self.engine.decide(ai("medium", 0.59))
        self.assertEqual(result, FinalAction.PASS)

    def test_medium_zero_confidence_passes(self):
        result = self.engine.decide(ai("medium", 0.0))
        self.assertEqual(result, FinalAction.PASS)

    def test_medium_high_confidence_aggressive_action_still_flags_not_junks(self):
        # Medium threat cannot reach MOVE_TO_JUNK regardless of action or confidence
        result = self.engine.decide(ai("medium", 0.99, "move_to_junk"))
        self.assertEqual(result, FinalAction.FLAG)


class TestDecisionEngineThresholdVariations(unittest.TestCase):
    """Verify behaviour changes correctly when thresholds are adjusted."""

    def test_aggressive_config_flags_at_lower_confidence(self):
        engine = DecisionEngine(flag_threshold=0.4, junk_threshold=0.6)
        result = engine.decide(ai("medium", 0.45))
        self.assertEqual(result, FinalAction.FLAG)

    def test_aggressive_config_junks_high_threat_at_lower_confidence(self):
        engine = DecisionEngine(flag_threshold=0.4, junk_threshold=0.6)
        result = engine.decide(ai("high", 0.65))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_conservative_config_requires_higher_confidence_to_flag(self):
        engine = DecisionEngine(flag_threshold=0.8, junk_threshold=0.95)
        result = engine.decide(ai("medium", 0.70))
        self.assertEqual(result, FinalAction.PASS)

    def test_conservative_config_flags_when_confidence_meets_threshold(self):
        engine = DecisionEngine(flag_threshold=0.8, junk_threshold=0.95)
        result = engine.decide(ai("medium", 0.85))
        self.assertEqual(result, FinalAction.FLAG)

    def test_conservative_config_high_threat_below_junk_threshold_flags(self):
        engine = DecisionEngine(flag_threshold=0.8, junk_threshold=0.95)
        result = engine.decide(ai("high", 0.85))
        self.assertEqual(result, FinalAction.FLAG)


class TestDecisionEngineCaseInsensitivity(unittest.TestCase):
    """Threat level and action strings should be handled case-insensitively."""

    def setUp(self):
        self.engine = DecisionEngine(flag_threshold=0.6, junk_threshold=0.8)

    def test_uppercase_threat_level(self):
        result = self.engine.decide(ai("CRITICAL", 0.5))
        self.assertEqual(result, FinalAction.MOVE_TO_JUNK)

    def test_mixed_case_threat_level(self):
        result = self.engine.decide(ai("None", 0.99))
        self.assertEqual(result, FinalAction.PASS)

    def test_uppercase_pass_action_overrides(self):
        result = self.engine.decide(ai("critical", 0.99, "PASS"))
        self.assertEqual(result, FinalAction.PASS)


class TestDecisionEngineReturnType(unittest.TestCase):
    """Confirm the return value is always a FinalAction enum member."""

    def setUp(self):
        self.engine = DecisionEngine(flag_threshold=0.6, junk_threshold=0.8)

    def test_returns_final_action_enum(self):
        for threat, confidence in [
            ("none", 0.5), ("low", 0.9), ("medium", 0.7),
            ("high", 0.9), ("critical", 0.1),
        ]:
            with self.subTest(threat=threat, confidence=confidence):
                result = self.engine.decide(ai(threat, confidence))
                self.assertIsInstance(result, FinalAction)


if __name__ == "__main__":
    unittest.main()
