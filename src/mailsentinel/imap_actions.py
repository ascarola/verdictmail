"""
imap_actions.py — IMAP keyword flag and move-to-Junk operations.
"""

from __future__ import annotations

import logging

from imapclient import IMAPClient

from .decision_engine import FinalAction

logger = logging.getLogger(__name__)

_SUSPECT_FLAG = b"$VerdictMail-Suspect"
_JUNK_FOLDER = "[Gmail]/Spam"


class ImapActionWriter:
    def apply(self, uid: int, action: FinalAction, client: IMAPClient) -> None:
        """Apply the resolved action to the given message UID."""
        if action == FinalAction.PASS:
            logger.info("UID %d: action=pass — no IMAP changes made", uid)
            return

        if action == FinalAction.FLAG:
            self._flag_message(uid, client)

        elif action == FinalAction.MOVE_TO_JUNK:
            self._move_to_junk(uid, client)

    # ------------------------------------------------------------------
    # FLAG — set custom IMAP keyword
    # ------------------------------------------------------------------

    def _flag_message(self, uid: int, client: IMAPClient) -> None:
        try:
            client.set_flags([uid], [_SUSPECT_FLAG])
            logger.info("UID %d: flagged with %s", uid, _SUSPECT_FLAG.decode())
        except Exception as exc:
            logger.error("UID %d: failed to set flag: %s", uid, exc)
            raise

    # ------------------------------------------------------------------
    # MOVE TO JUNK — copy then delete
    # ------------------------------------------------------------------

    def _move_to_junk(self, uid: int, client: IMAPClient) -> None:
        # 1. Copy to junk folder
        try:
            copy_result = client.copy([uid], _JUNK_FOLDER)
            logger.debug("UID %d: copy result: %s", uid, copy_result)
        except Exception as exc:
            logger.error(
                "UID %d: COPY to %s failed — aborting move: %s", uid, _JUNK_FOLDER, exc
            )
            raise

        # 2. Only delete the original after a confirmed copy
        try:
            client.delete_messages([uid])
            client.expunge()
            logger.info("UID %d: moved to %s", uid, _JUNK_FOLDER)
        except Exception as exc:
            logger.error(
                "UID %d: delete/expunge failed after copy (message may be duplicated): %s",
                uid,
                exc,
            )
            raise
