"""
main.py — VerdictMail daemon entry point.

Loads config, wires all components, runs the IMAP IDLE loop with a
ThreadPoolExecutor for concurrent message processing.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

PAUSE_FLAG = Path("/var/log/verdictmail/paused")

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _load_config(config_path: str) -> dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Whitelist helper
# ---------------------------------------------------------------------------

def _match_whitelist(rules: list[dict], parsed) -> dict | None:
    """Return the first matching whitelist rule, or None.

    A rule matches when ALL of its specified criteria match the message.
    Supported criteria: sender (exact email), sender_domain, subject_contains.
    """
    sender = getattr(parsed, "sender_address", "") or ""        # already .lower()
    sender_domain = getattr(parsed, "sender_domain", "") or ""  # already lower
    subject = (getattr(parsed, "subject", "") or "").lower()

    for rule in rules:
        r_sender = (rule.get("sender") or "").lower()
        r_domain = (rule.get("sender_domain") or "").lower()
        r_subj = (rule.get("subject_contains") or "").lower()
        # Skip rules with no criteria at all
        if not (r_sender or r_domain or r_subj):
            continue
        if r_sender and r_sender != sender:
            continue
        if r_domain and r_domain != sender_domain:
            continue
        if r_subj and r_subj not in subject:
            continue
        return rule
    return None


# ---------------------------------------------------------------------------
# Process one message (runs inside a thread-pool worker)
# ---------------------------------------------------------------------------

def _process_message(
    uid: int,
    imap_params: dict,
    enrichment_pipeline,
    ai_analyzer,
    decision_engine,
    action_writer,
    db_conn,
    model_name: str,
    inflight_uids: set,
    inflight_lock: threading.Lock,
    done_uids: set,
    whitelist_rules: list,
) -> None:
    from .audit_logger import log_decision
    from imapclient import IMAPClient

    start_ms = time.monotonic()
    log = logging.getLogger(__name__ + ".worker")
    log.info("Processing UID %d", uid)

    raw_bytes: bytes = b""
    action_taken = "error"
    ai_result = None
    parsed = None
    worker_client = None

    try:
        # 1. Open a dedicated IMAP connection for this worker (keeps IDLE socket clean)
        worker_client = IMAPClient(
            imap_params["host"], port=imap_params["port"], ssl=True, use_uid=True
        )
        worker_client.login(imap_params["username"], imap_params["password"])
        worker_client.select_folder(imap_params["folder"])

        # 2. Fetch — BODY.PEEK[] is the RFC 3501 way to get the full message
        #    without setting the \Seen flag (RFC822 would mark it as read)
        response = worker_client.fetch([uid], ["BODY.PEEK[]"])
        if uid not in response:
            raise ValueError(f"UID {uid} not found in FETCH response")
        raw_bytes = response[uid][b"BODY[]"]

        # 3. Parse
        from .message_parser import parse_raw_message
        parsed = parse_raw_message(raw_bytes)

        # 3a. Whitelist check — bypass enrichment/AI for trusted senders
        whitelist_match = _match_whitelist(whitelist_rules, parsed) if whitelist_rules else None
        if whitelist_match:
            comment = (
                whitelist_match.get("comment")
                or whitelist_match.get("sender")
                or whitelist_match.get("sender_domain")
                or "rule match"
            )
            log.info("UID %d: whitelisted (%s) — skipping analysis", uid, comment)
            action_taken = "pass"
            ai_result = types.SimpleNamespace(
                threat_level="none",
                threat_types=[],
                confidence=1.0,
                signals={},
                reasoning=f"Whitelisted: {comment}",
                raw_response="",
            )
            model_name = "whitelist"
        else:
            # 4. Enrich
            enrichment = enrichment_pipeline.run(raw_bytes, parsed)

            # 5. AI analysis
            ai_result = ai_analyzer.analyze(parsed, enrichment)

            # 6. Decide
            final_action = decision_engine.decide(ai_result)
            action_taken = final_action.value

            # 7. Apply IMAP action using this worker's own connection
            try:
                action_writer.apply(uid, final_action, worker_client)
            except Exception as exc:
                log.error("UID %d: IMAP action %s failed: %s", uid, final_action.value, exc)
                action_taken = f"error:{final_action.value}"

    except Exception as exc:
        log.error("UID %d: processing failed: %s", uid, exc, exc_info=True)

    finally:
        # Mark UID as done and release from in-flight
        with inflight_lock:
            inflight_uids.discard(uid)
            done_uids.add(uid)

        # Close the worker's private IMAP connection
        if worker_client is not None:
            try:
                worker_client.logout()
            except Exception:
                pass

        elapsed_ms = int((time.monotonic() - start_ms) * 1000)

        # 8. Audit log
        record: dict[str, Any] = {
            "message_id": getattr(parsed, "message_id", "") if parsed else "",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "sender": getattr(parsed, "sender_address", "") if parsed else "",
            "subject": getattr(parsed, "subject", "") if parsed else "",
            "threat_level": ai_result.threat_level if ai_result else "unknown",
            "threat_types": ai_result.threat_types if ai_result else [],
            "confidence": ai_result.confidence if ai_result else 0.0,
            "signals": ai_result.signals if ai_result else {},
            "reasoning": ai_result.reasoning if ai_result else "",
            "model_name": model_name,
            "action_taken": action_taken,
            "processing_ms": elapsed_ms,
            "raw_ai_response": ai_result.raw_response if ai_result else "",
        }
        try:
            log_decision(db_conn, record)
        except Exception as exc:
            log.error("UID %d: failed to write audit log: %s", uid, exc)

        log.info(
            "UID %d done in %dms | threat=%s confidence=%.2f action=%s",
            uid,
            elapsed_ms,
            record["threat_level"],
            record["confidence"],
            action_taken,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # -----------------------------------------------------------------------
    # 1. Locate config file
    # -----------------------------------------------------------------------
    script_dir = Path(__file__).resolve().parent
    # Walk up to find config/ directory relative to project root
    project_root = script_dir.parent.parent  # src/verdictmail → src → project root
    config_path = os.environ.get(
        "VERDICTMAIL_CONFIG",
        str(project_root / "config" / "verdictmail.yaml"),
    )

    try:
        cfg = _load_config(config_path)
    except FileNotFoundError:
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # 2. Load credentials from .env
    # -----------------------------------------------------------------------
    env_path = os.environ.get("VERDICTMAIL_ENV", str(project_root / ".env"))
    if Path(env_path).exists():
        load_dotenv(env_path)
    else:
        # Fall back to environment already set (e.g. systemd EnvironmentFile)
        load_dotenv()

    gmail_user = os.environ.get("GMAIL_USERNAME")
    gmail_pass = os.environ.get("GMAIL_APP_PASSWORD")

    if not gmail_user or not gmail_pass:
        print(
            "ERROR: GMAIL_USERNAME and GMAIL_APP_PASSWORD must be set in the environment or .env file",
            file=sys.stderr,
        )
        sys.exit(1)

    # -----------------------------------------------------------------------
    # 3. Set up logging
    # -----------------------------------------------------------------------
    from .audit_logger import init_db, setup_logging

    paths_cfg = cfg.get("paths", {})
    log_file = paths_cfg.get("log_file", "/var/log/verdictmail/verdictmail.log")
    db_file = paths_cfg.get("db_file", "/var/log/verdictmail/verdictmail.db")
    log_max_bytes = paths_cfg.get("log_max_bytes", 10 * 1024 * 1024)
    log_backup_count = paths_cfg.get("log_backup_count", 5)

    setup_logging(log_file, log_max_bytes, log_backup_count)
    logger.info("VerdictMail starting up")

    # -----------------------------------------------------------------------
    # 4. Init SQLite
    # -----------------------------------------------------------------------
    db_conn = init_db(db_file)
    logger.info("SQLite database opened at %s", db_file)

    # -----------------------------------------------------------------------
    # 5. Build components
    # -----------------------------------------------------------------------
    imap_cfg = cfg.get("imap", {})
    # Support new "ai:" section; fall back to legacy "ollama:" section
    ai_cfg = cfg.get("ai", cfg.get("ollama", {}))
    thresholds_cfg = cfg.get("thresholds", {})
    dnsbl_cfg = cfg.get("dnsbl", {})
    worker_threads = cfg.get("worker_threads", 4)

    from .imap_client import ImapIdleClient
    from .enrichment import EnrichmentPipeline
    from .ai_analyzer import AiAnalyzer
    from .decision_engine import DecisionEngine
    from .imap_actions import ImapActionWriter

    imap_params = {
        "host": imap_cfg.get("host", "imap.gmail.com"),
        "port": imap_cfg.get("port", 993),
        "username": gmail_user,
        "password": gmail_pass,
        "folder": imap_cfg.get("folder", "INBOX"),
    }

    imap_client = ImapIdleClient(
        host=imap_params["host"],
        port=imap_params["port"],
        username=imap_params["username"],
        password=imap_params["password"],
        folder=imap_params["folder"],
    )

    enrichment_pipeline = EnrichmentPipeline(
        dnsbl_lists=dnsbl_cfg.get("lists", []),
    )

    ai_provider = ai_cfg.get("provider", "ollama")
    ai_model = ai_cfg.get("model", "qwen2.5-coder:14b")
    ai_timeout = int(ai_cfg.get("timeout_seconds", 120))
    # Resolve API key from environment based on provider
    if ai_provider == "anthropic":
        ai_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    elif ai_provider == "openai":
        ai_api_key = os.environ.get("OPENAI_API_KEY", "")
    else:
        ai_api_key = os.environ.get("OLLAMA_API_KEY", "")

    ai_analyzer = AiAnalyzer(
        provider=ai_provider,
        model=ai_model,
        timeout_seconds=ai_timeout,
        base_url=ai_cfg.get("ollama_base_url", ai_cfg.get("base_url", "http://localhost:11434")),
        api_key=ai_api_key,
    )
    logger.info("AI provider: %s | model: %s", ai_provider, ai_model)

    decision_engine = DecisionEngine(
        flag_threshold=thresholds_cfg.get("flag", 0.55),
        junk_threshold=thresholds_cfg.get("junk", 0.80),
    )

    action_writer = ImapActionWriter()
    model_name = ai_model

    whitelist_cfg = cfg.get("whitelist", {})
    whitelist_enabled = whitelist_cfg.get("enabled", True)
    whitelist_rules: list[dict] = whitelist_cfg.get("rules", []) if whitelist_enabled else []
    if whitelist_rules:
        logger.info("Whitelist active: %d rule(s)", len(whitelist_rules))
    else:
        logger.info("Whitelist disabled or empty")

    # -----------------------------------------------------------------------
    # 6. Signal handling for graceful shutdown
    # -----------------------------------------------------------------------
    shutdown_event = threading.Event()
    inflight_uids: set[int] = set()
    done_uids: set[int] = set()      # UIDs fully processed this session
    inflight_lock = threading.Lock()

    def _submit_uid(executor, uid: int) -> None:
        """Submit a UID for processing, skipping if in-flight, already done, or paused."""
        if PAUSE_FLAG.exists():
            logger.info("UID %d: daemon paused — holding message unread", uid)
            return
        with inflight_lock:
            if uid in inflight_uids or uid in done_uids:
                logger.debug("UID %d already processed/in-flight — skipping", uid)
                return
            inflight_uids.add(uid)
        executor.submit(
            _process_message,
            uid,
            imap_params,
            enrichment_pipeline,
            ai_analyzer,
            decision_engine,
            action_writer,
            db_conn,
            model_name,
            inflight_uids,
            inflight_lock,
            done_uids,
            whitelist_rules,
        )

    def _handle_signal(signum, frame):
        logger.info("Received signal %d — shutting down gracefully", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # -----------------------------------------------------------------------
    # 7. Connect to IMAP
    # -----------------------------------------------------------------------
    try:
        imap_client.connect()
    except Exception as exc:
        logger.critical("Initial IMAP connection failed: %s", exc)
        imap_client.reconnect_with_backoff()

    # -----------------------------------------------------------------------
    # 8. Main IDLE loop
    # -----------------------------------------------------------------------
    logger.info("Entering IMAP IDLE loop with %d worker threads", worker_threads)

    startup_scan_limit = cfg.get("startup_scan_limit", 20)

    with ThreadPoolExecutor(max_workers=worker_threads, thread_name_prefix="ms-worker") as executor:
        # On startup, catch any messages that arrived while the daemon was down.
        # Only process the most recent N unread messages to avoid blasting through
        # a large backlog (e.g. when switching to a busy mailbox).
        try:
            startup_uids = imap_client.client.search(["UNSEEN"])
            if startup_uids:
                limited = startup_uids[-startup_scan_limit:] if startup_scan_limit > 0 else startup_uids
                skipped = len(startup_uids) - len(limited)
                if skipped:
                    logger.warning(
                        "Startup scan: %d unseen found, limit=%d — skipping %d oldest, processing %d most recent",
                        len(startup_uids), startup_scan_limit, skipped, len(limited),
                    )
                else:
                    logger.info("Startup scan: %d unseen message(s) queued", len(limited))
                for uid in limited:
                    _submit_uid(executor, uid)
        except Exception as exc:
            logger.warning("Startup UNSEEN scan failed: %s", exc)

        while not shutdown_event.is_set():
            try:
                new_uids = imap_client.wait_for_new_messages(shutdown_event=shutdown_event)
                for uid in new_uids:
                    _submit_uid(executor, uid)
            except Exception as exc:
                if shutdown_event.is_set():
                    break
                # Gmail pushes unsolicited FETCH/FLAGS updates to the IDLE socket
                # when worker connections touch the same mailbox. These are harmless —
                # just re-enter IDLE without a full reconnect.
                if "unexpected response" in str(exc):
                    logger.debug("Ignoring unsolicited IMAP response (worker activity): %s", exc)
                    continue
                logger.error("IMAP error in main loop: %s — reconnecting", exc)
                try:
                    imap_client.reconnect_with_backoff()
                except Exception as reconnect_exc:
                    logger.critical("Failed to reconnect: %s", reconnect_exc)
                    if not shutdown_event.is_set():
                        continue

    logger.info("VerdictMail shut down cleanly")
    db_conn.close()


if __name__ == "__main__":
    main()
