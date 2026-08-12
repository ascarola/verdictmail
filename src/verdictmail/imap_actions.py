"""
imap_actions.py — IMAP flag and move operations.
"""

from __future__ import annotations

import logging

from imapclient import IMAPClient

from .decision_engine import FinalAction

logger = logging.getLogger(__name__)

_DEFAULT_JUNK_FOLDER = "[Gmail]/Spam"
_DEFAULT_TRASH_FOLDER = "[Gmail]/Trash"


class ImapActionWriter:
    def __init__(
        self,
        junk_folder: str = _DEFAULT_JUNK_FOLDER,
        suspect_folder: str = "",
        trash_folder: str = _DEFAULT_TRASH_FOLDER,
    ):
        self._junk_folder = junk_folder
        self._suspect_folder = suspect_folder
        self._trash_folder = trash_folder

    def apply(self, uid: int, action: FinalAction, client: IMAPClient) -> None:
        """Apply the resolved action to the given message UID."""
        if action == FinalAction.PASS:
            logger.info("UID %d: action=pass — no IMAP changes made", uid)
            return

        if action == FinalAction.FLAG:
            self._flag_message(uid, client)

        elif action == FinalAction.MOVE_TO_JUNK:
            self._move_to_folder(uid, self._junk_folder, client)

        elif action == FinalAction.MOVE_TO_TRASH:
            self._move_to_folder(uid, self._trash_folder, client)

    # ------------------------------------------------------------------
    # FLAG — move to suspect folder, or star with \Flagged
    # ------------------------------------------------------------------

    def _flag_message(self, uid: int, client: IMAPClient) -> None:
        if self._suspect_folder:
            try:
                client.copy([uid], self._suspect_folder)
            except Exception as exc:
                logger.error("UID %d: COPY to '%s' failed — aborting move: %s", uid, self._suspect_folder, exc)
                raise
            try:
                client.delete_messages([uid])
                client.expunge()
                logger.info("UID %d: moved to suspect folder '%s'", uid, self._suspect_folder)
            except Exception as exc:
                logger.error("UID %d: delete/expunge after copy failed (message may be duplicated): %s", uid, exc)
                raise
        else:
            try:
                client.set_flags([uid], [b"\\Flagged"])
                logger.info("UID %d: starred (\\Flagged)", uid)
            except Exception as exc:
                logger.error("UID %d: failed to set \\Flagged: %s", uid, exc)
                raise

    # ------------------------------------------------------------------
    # MOVE — copy to a destination folder, then delete the original
    # ------------------------------------------------------------------
    # Used for both Junk/Spam and Trash. On Gmail, copying into [Gmail]/Spam
    # or [Gmail]/Trash strips the INBOX label automatically, so the follow-up
    # delete/expunge on INBOX is a harmless no-op guarded by try/except.
    # (A bare \Deleted+expunge on INBOX would NOT move mail to Trash — it only
    # removes the INBOX label and the message survives in All Mail forever.)

    def _move_to_folder(self, uid: int, folder: str, client: IMAPClient) -> None:
        # 1. Copy to the destination folder
        try:
            copy_result = client.copy([uid], folder)
            logger.debug("UID %d: copy result: %s", uid, copy_result)
        except Exception as exc:
            logger.error(
                "UID %d: COPY to %s failed — aborting move: %s", uid, folder, exc
            )
            raise

        # 2. Only delete the original after a confirmed copy
        try:
            client.delete_messages([uid])
            client.expunge()
            logger.info("UID %d: moved to %s", uid, folder)
        except Exception as exc:
            logger.error(
                "UID %d: delete/expunge failed after copy (message may be duplicated): %s",
                uid,
                exc,
            )
            raise
