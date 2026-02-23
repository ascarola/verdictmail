"""
imap_client.py — IMAP IDLE connection with exponential backoff reconnect.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Optional

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError

logger = logging.getLogger(__name__)

# Backoff caps (seconds)
_BACKOFF_STEPS = [2, 4, 8, 16, 32, 60]
_IDLE_TIMEOUT = 300  # seconds between IDLE keepalive NOOPs


class ImapIdleClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        folder: str = "INBOX",
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.folder = folder
        self._client: Optional[IMAPClient] = None
        self._backoff_index = 0

    # ------------------------------------------------------------------
    # Connect / reconnect
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Establish an authenticated IMAP connection and select the folder."""
        logger.info("Connecting to %s:%d as %s", self.host, self.port, self.username)
        client = IMAPClient(self.host, port=self.port, ssl=True, use_uid=True)
        client.login(self.username, self.password)
        client.select_folder(self.folder)
        self._client = client
        self._backoff_index = 0  # reset on successful connect
        logger.info("IMAP connected and folder '%s' selected", self.folder)

    def reconnect_with_backoff(self) -> None:
        """Disconnect (if connected) and reconnect with exponential backoff + jitter."""
        self._disconnect_quietly()
        delay = _BACKOFF_STEPS[min(self._backoff_index, len(_BACKOFF_STEPS) - 1)]
        delay += random.uniform(0, delay * 0.25)  # up to 25% jitter
        logger.warning("Reconnecting in %.1fs (attempt #%d)...", delay, self._backoff_index + 1)
        time.sleep(delay)
        self._backoff_index = min(self._backoff_index + 1, len(_BACKOFF_STEPS) - 1)

        while True:
            try:
                self.connect()
                return
            except Exception as exc:
                delay = _BACKOFF_STEPS[min(self._backoff_index, len(_BACKOFF_STEPS) - 1)]
                delay += random.uniform(0, delay * 0.25)
                logger.error("Reconnect failed: %s — retrying in %.1fs", exc, delay)
                time.sleep(delay)
                self._backoff_index = min(self._backoff_index + 1, len(_BACKOFF_STEPS) - 1)

    def _disconnect_quietly(self) -> None:
        if self._client is not None:
            try:
                self._client.logout()
            except Exception:
                pass
            self._client = None

    # ------------------------------------------------------------------
    # IDLE loop
    # ------------------------------------------------------------------

    def wait_for_new_messages(
        self,
        shutdown_event: threading.Event | None = None,
        poll_seconds: int = 30,
    ) -> list[int]:
        """
        Enter IDLE mode and block until new messages arrive or shutdown.

        Uses short poll intervals so the daemon can respond to SIGTERM
        within ~poll_seconds seconds rather than waiting the full IDLE
        keepalive timeout.  Sends a NOOP every _IDLE_TIMEOUT seconds to
        keep the connection alive.

        Returns a list of new/unseen UIDs, or [] if shutting down.
        """
        assert self._client is not None, "Not connected — call connect() first"

        elapsed_since_noop = 0

        while True:
            if shutdown_event and shutdown_event.is_set():
                return []

            logger.debug("Entering IMAP IDLE (poll=%ds)", poll_seconds)
            self._client.idle()
            responses = self._client.idle_check(timeout=poll_seconds)
            self._client.idle_done()

            if shutdown_event and shutdown_event.is_set():
                return []

            if not responses:
                elapsed_since_noop += poll_seconds
                if elapsed_since_noop >= _IDLE_TIMEOUT:
                    logger.debug("IDLE keepalive — sending NOOP")
                    self._client.noop()
                    elapsed_since_noop = 0
            else:
                elapsed_since_noop = 0
                logger.debug("IDLE notification received: %s", responses)

            # Always search for UNSEEN after each idle_done() — this catches
            # messages that arrived during the brief gap between idle_done()
            # and the next idle() call (Gmail may not re-push those EXISTS).
            try:
                uids = self._client.search(["UNSEEN"])
            except Exception as exc:
                logger.error("SEARCH UNSEEN failed: %s", exc)
                uids = []

            if uids:
                logger.debug("UNSEEN after idle poll: %s", uids)
                return list(uids)

    # ------------------------------------------------------------------
    # Fetch raw bytes
    # ------------------------------------------------------------------

    def fetch_raw(self, uid: int) -> bytes:
        """Fetch the raw bytes for a single UID without marking it as seen."""
        assert self._client is not None
        response = self._client.fetch([uid], ["BODY.PEEK[]"])
        if uid not in response:
            raise ValueError(f"UID {uid} not found in FETCH response")
        return response[uid][b"BODY[]"]

    # ------------------------------------------------------------------
    # Expose underlying client for imap_actions
    # ------------------------------------------------------------------

    @property
    def client(self) -> IMAPClient:
        assert self._client is not None
        return self._client
