"""
decision_engine.py — Threshold-based action decision from AI results.
"""

from __future__ import annotations

import logging
from enum import Enum

logger = logging.getLogger(__name__)


class FinalAction(str, Enum):
    PASS = "pass"
    FLAG = "flag"
    MOVE_TO_JUNK = "move_to_junk"


class DecisionEngine:
    def __init__(self, flag_threshold: float, junk_threshold: float):
        self.flag_threshold = flag_threshold
        self.junk_threshold = junk_threshold

    def decide(self, ai_result) -> FinalAction:
        """
        Determine the final action based on AI threat level, confidence, and recommendation.

        threat_level is the primary gate — confidence fine-tunes within that level.
        This keeps low-threat commercial/marketing mail from being aggressively actioned
        while still catching genuine phishing, malware, and BEC with confidence.

        Rules (in priority order):
          1. threat_level == 'none' OR ai_action == 'pass'          → PASS
          2. threat_level == 'low'                                   → PASS
             (suspicious signals but not clearly malicious; Google handles spam)
          3. threat_level == 'critical'                              → MOVE_TO_JUNK
          4. threat_level == 'high' AND confidence >= junk_threshold → MOVE_TO_JUNK
          5. threat_level == 'high' AND AI wants aggressive action
             AND confidence >= flag_threshold                        → MOVE_TO_JUNK
          6. threat_level in ('medium','high') AND confidence >= flag_threshold → FLAG
          7. everything else                                         → PASS
        """
        confidence = ai_result.confidence
        ai_action = ai_result.recommended_action.lower()
        threat_level = ai_result.threat_level.lower()

        # No threat or AI says pass → always let through
        if threat_level == "none" or ai_action == "pass":
            action = FinalAction.PASS

        # Low threat → pass; suspicious indicators but not actionable
        elif threat_level == "low":
            action = FinalAction.PASS

        # Critical threat → always junk
        elif threat_level == "critical":
            action = FinalAction.MOVE_TO_JUNK

        # High confidence high threat → junk
        elif threat_level == "high" and confidence >= self.junk_threshold:
            action = FinalAction.MOVE_TO_JUNK

        # High threat + AI wants aggressive action + sufficient confidence → junk
        elif (
            threat_level == "high"
            and confidence >= self.flag_threshold
            and ai_action in ("quarantine", "move_to_junk", "block")
        ):
            action = FinalAction.MOVE_TO_JUNK

        # Medium or high threat + sufficient confidence → flag for human review
        elif threat_level in ("medium", "high") and confidence >= self.flag_threshold:
            action = FinalAction.FLAG

        # Everything else → pass
        else:
            action = FinalAction.PASS

        logger.info(
            "Decision: threat=%s confidence=%.2f ai_action=%s → %s",
            threat_level,
            confidence,
            ai_action,
            action.value,
        )
        return action
