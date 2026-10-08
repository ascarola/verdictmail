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
    # Only produced by the blacklist path (never by threshold logic below).
    # Moves the message to the Trash folder instead of Junk/Spam.
    MOVE_TO_TRASH = "move_to_trash"


class DecisionEngine:
    def __init__(
        self,
        flag_threshold: float,
        junk_threshold: float,
        graymail_enabled: bool = False,
        graymail_flag_threshold: float = 0.60,
        graymail_junk_threshold: float = 0.85,
    ):
        self.flag_threshold = flag_threshold
        self.junk_threshold = junk_threshold
        # Graymail = unsolicited bulk/commercial mail (marketing, cold sales outreach,
        # newsletters, notification digests). Evaluated on a separate axis and only when
        # the threat verdict would otherwise PASS, so it never softens a real threat.
        self.graymail_enabled = graymail_enabled
        self.graymail_flag_threshold = graymail_flag_threshold
        self.graymail_junk_threshold = graymail_junk_threshold

    def decide(self, ai_result, enrichment=None) -> FinalAction:
        """
        Determine the final action based on AI threat level, confidence, and recommendation.

        `enrichment` is optional and backward-compatible: when omitted, behavior is
        identical to before. When provided, it is used only to apply a non-destructive
        "evidence floor" (see below) — it can never downgrade or soften the model's verdict.

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
             AND confidence >= midpoint of flag/junk thresholds      → MOVE_TO_JUNK
             (the AI's explicit junk/block recommendation earns a discount on the
             junk threshold, but not all the way down to the flag threshold —
             otherwise the junk threshold would be bypassed entirely)
          6. threat_level in ('medium','high') AND confidence >= flag_threshold → FLAG
          7. everything else                                         → PASS

        Graymail axis (only applied when the rules above yield PASS, and only when
        graymail filtering is enabled — a real threat verdict always takes precedence):
          G1. graymail_category != 'none' AND graymail_confidence >= graymail_junk_threshold → MOVE_TO_JUNK
          G2. graymail_category != 'none' AND graymail_confidence >= graymail_flag_threshold → FLAG (Suspect)
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
            and confidence >= (self.flag_threshold + self.junk_threshold) / 2
            and ai_action in ("quarantine", "move_to_junk", "block")
        ):
            action = FinalAction.MOVE_TO_JUNK

        # Medium or high threat + sufficient confidence → flag for human review
        elif threat_level in ("medium", "high") and confidence >= self.flag_threshold:
            action = FinalAction.FLAG

        # Everything else → pass
        else:
            action = FinalAction.PASS

        # Graymail axis — only when the threat verdict is PASS. A real threat verdict
        # (FLAG/JUNK) is never downgraded or overridden by a graymail judgment.
        graymail_category = getattr(ai_result, "graymail_category", "none")
        graymail_confidence = getattr(ai_result, "graymail_confidence", 0.0)
        if (
            self.graymail_enabled
            and action == FinalAction.PASS
            and graymail_category != "none"
        ):
            if graymail_confidence >= self.graymail_junk_threshold:
                action = FinalAction.MOVE_TO_JUNK
            elif graymail_confidence >= self.graymail_flag_threshold:
                action = FinalAction.FLAG
            if action != FinalAction.PASS:
                logger.info(
                    "Graymail override: category=%s graymail_confidence=%.2f → %s",
                    graymail_category,
                    graymail_confidence,
                    action.value,
                )

        # Evidence floor (prompt-injection / evasion defense).
        # URLhaus (known-malware URLs) and VirusTotal (multi-vendor detections) are
        # curated threat-intel feeds, computed in code from the message itself — they
        # cannot be talked down by text in the email body. If such a hit is present, the
        # message must not silently PASS into the inbox, so we floor it at FLAG (human
        # review). This ONLY ever raises a PASS to FLAG; it never junks, deletes, or
        # downgrades a stronger verdict. These signals exist only when the operator has
        # configured URLhaus/VirusTotal API keys, so deployments without those
        # integrations are entirely unaffected.
        if enrichment is not None and action == FinalAction.PASS:
            urlhaus = bool(getattr(enrichment, "urlhaus_hits", None))
            virustotal = bool(getattr(enrichment, "virustotal_hits", None))
            if urlhaus or virustotal:
                action = FinalAction.FLAG
                logger.warning(
                    "Evidence floor: threat-intel hit (urlhaus=%s virustotal=%s) overrides "
                    "model PASS → FLAG (model verdict=%s/%.2f)",
                    urlhaus, virustotal, threat_level, confidence,
                )

        logger.info(
            "Decision: threat=%s confidence=%.2f ai_action=%s graymail=%s/%.2f → %s",
            threat_level,
            confidence,
            ai_action,
            graymail_category,
            graymail_confidence,
            action.value,
        )
        return action
