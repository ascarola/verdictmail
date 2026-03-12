"""
app.py — VerdictMail Flask web UI.

Routes:
  GET  /                         → dashboard
  GET  /audit                    → paginated + filtered audit log
  GET  /config                   → config editor
  POST /config                   → save YAML
  GET  /credentials              → credentials editor
  POST /credentials              → save .env
  POST /credentials/change-password → change web UI password
  GET  /test                     → manual test form
  POST /test                     → run pipeline, show results
  POST /service/restart          → signal daemon restart
  GET  /login                    → login page
  POST /login                    → authenticate
  GET  /logout                   → clear session
  GET  /setup                    → first-time password setup
  POST /setup                    → save initial password hash
  GET  /about                    → about page
"""

from __future__ import annotations

import email.mime.text
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from dotenv import dotenv_values
from flask import (
    Flask, flash, jsonify, redirect, render_template,
    request, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[3]   # /opt/verdictmail
CONFIG_PATH = BASE_DIR / "config" / "verdictmail.yaml"
ENV_PATH = BASE_DIR / ".env"
DB_PATH = Path("/var/log/verdictmail/verdictmail.db")
PAUSE_FLAG = Path("/var/log/verdictmail/paused")

# Ensure src/ is on the path so we can import siblings
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


def _safe_next_url(url: str, fallback: str) -> str:
    """Return url only if it is a safe relative path (no scheme, no host).
    Prevents open-redirect via protocol-relative URLs such as //evil.com."""
    parsed = urlparse(url)
    if url.startswith("/") and not parsed.scheme and not parsed.netloc:
        return url
    return fallback


def _load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f) or {}


def _save_config(cfg: dict) -> None:
    # Write to a temp file in the same directory then atomically rename into
    # place. os.replace() is atomic on Linux (single filesystem), so a crash
    # mid-write can never leave the config file truncated or corrupt.
    fd, tmp_path = tempfile.mkstemp(dir=CONFIG_PATH.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
        os.replace(tmp_path, CONFIG_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _get_tz(cfg: dict) -> ZoneInfo:
    tz_name = cfg.get("timezone", "UTC")
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, Exception):
        return ZoneInfo("UTC")


def _get_or_create_secret_key() -> str:
    """Return a stable secret key, generating and persisting one on first run."""
    try:
        cfg = _load_config()
        key = cfg.get("ui", {}).get("secret_key")
        if not key:
            import secrets
            key = secrets.token_hex(32)
            cfg.setdefault("ui", {})["secret_key"] = key
            _save_config(cfg)
        return key
    except Exception:
        import secrets
        return secrets.token_hex(32)  # non-persistent fallback


app.secret_key = _get_or_create_secret_key()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def require_auth(f):
    """Decorator: redirect to /setup (no password) or /login (not authed)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            cfg = _load_config()
        except Exception:
            cfg = {}
        pw_hash = cfg.get("ui", {}).get("password_hash", "")
        if not pw_hash:
            if request.is_json or request.headers.get("Accept") == "application/json":
                return jsonify(ok=False, msg="Web UI password not configured."), 401
            return redirect(url_for("setup"))
        if not session.get("authed"):
            if request.is_json or request.headers.get("Accept") == "application/json":
                return jsonify(ok=False, msg="Not authenticated."), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 30 per hour", methods=["POST"])
def login():
    try:
        cfg = _load_config()
    except Exception:
        cfg = {}
    pw_hash = cfg.get("ui", {}).get("password_hash", "")
    if not pw_hash:
        return redirect(url_for("setup"))
    if session.get("authed"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(pw_hash, password):
            session["authed"] = True
            next_url = request.args.get("next", "")
            return redirect(_safe_next_url(next_url, url_for("dashboard")))
        error = "Incorrect password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    try:
        cfg = _load_config()
    except Exception:
        cfg = {}
    # If a password is already configured, block unauthenticated setup
    if cfg.get("ui", {}).get("password_hash"):
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            pw_hash = generate_password_hash(password)
            cfg.setdefault("ui", {})["password_hash"] = pw_hash
            try:
                _save_config(cfg)
                flash("Password set. Please log in.", "success")
                return redirect(url_for("login"))
            except Exception as exc:
                error = f"Could not save config: {exc}"

    return render_template("setup.html", error=error)


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

@app.template_filter("local_dt")
def local_dt_filter(utc_str: str, tz_name: str = "UTC") -> str:
    """Convert a stored UTC ISO timestamp to the configured local timezone."""
    if not utc_str:
        return "—"
    try:
        dt = datetime.fromisoformat(utc_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(ZoneInfo(tz_name))
        return local.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return utc_str[:16] if utc_str else "—"


@app.context_processor
def inject_globals():
    """Inject tz_name and ai_model into every template automatically."""
    try:
        cfg = _load_config()
    except Exception:
        cfg = {}
    ai_cfg = cfg.get("ai", cfg.get("ollama", {}))
    return {
        "tz_name": cfg.get("timezone", "UTC"),
        "ai_model": ai_cfg.get("model", "—"),
    }


# ---------------------------------------------------------------------------
# Dashboard  GET /
# ---------------------------------------------------------------------------

@app.route("/")
@require_auth
def dashboard():
    cfg = _load_config()

    stats = {
        "total": 0,
        "today": 0,
        "pass": 0,
        "flag": 0,
        "move_to_junk": 0,
        "error": 0,
        "avg_ms": 0,
    }
    threat_counts = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    chart_labels: list[str] = []
    chart_pass: list[int] = []
    chart_flag: list[int] = []
    chart_junk: list[int] = []
    recent: list[sqlite3.Row] = []
    errors: list[sqlite3.Row] = []

    try:
        conn = _db_conn()
        local_tz = _get_tz(cfg)
        local_now = datetime.now(tz=local_tz)

        # Compute UTC bounds for "today" in the configured local timezone
        from datetime import time as _time
        local_midnight = datetime.combine(local_now.date(), _time(0, 0), tzinfo=local_tz)
        utc_day_start = local_midnight.astimezone(timezone.utc).isoformat()
        utc_day_end = (local_midnight + timedelta(days=1)).astimezone(timezone.utc).isoformat()

        stats["total"] = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        stats["today"] = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND timestamp < ?",
            (utc_day_start, utc_day_end),
        ).fetchone()[0]

        for row in conn.execute(
            "SELECT action_taken, COUNT(*) AS cnt FROM audit_log GROUP BY action_taken"
        ):
            key = (row["action_taken"] or "error").lower()
            if key.startswith("error"):
                key = "error"
            if key in stats:
                stats[key] = row["cnt"]
            else:
                stats["error"] += row["cnt"]

        avg_row = conn.execute("SELECT AVG(processing_ms) FROM audit_log").fetchone()
        stats["avg_ms"] = round(avg_row[0] or 0)

        for row in conn.execute(
            "SELECT threat_level, COUNT(*) AS cnt FROM audit_log GROUP BY threat_level"
        ):
            lvl = (row["threat_level"] or "none").lower()
            if lvl in threat_counts:
                threat_counts[lvl] = row["cnt"]

        # Last 7 days stacked bar — use local-timezone day boundaries
        for i in range(6, -1, -1):
            local_day = local_now.date() - timedelta(days=i)
            day_start = datetime.combine(local_day, _time(0, 0), tzinfo=local_tz).astimezone(timezone.utc).isoformat()
            day_end = datetime.combine(local_day + timedelta(days=1), _time(0, 0), tzinfo=local_tz).astimezone(timezone.utc).isoformat()
            chart_labels.append(local_day.strftime("%m-%d"))
            pass_cnt = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND timestamp < ? AND action_taken='pass'",
                (day_start, day_end),
            ).fetchone()[0]
            flag_cnt = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND timestamp < ? AND action_taken='flag'",
                (day_start, day_end),
            ).fetchone()[0]
            junk_cnt = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ? AND timestamp < ? AND action_taken='move_to_junk'",
                (day_start, day_end),
            ).fetchone()[0]
            chart_pass.append(pass_cnt)
            chart_flag.append(flag_cnt)
            chart_junk.append(junk_cnt)

        recent = conn.execute(
            "SELECT id,timestamp,sender,subject,threat_level,confidence,action_taken "
            "FROM audit_log ORDER BY id DESC LIMIT 10"
        ).fetchall()

        conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.commit()
        dismissed_row = conn.execute(
            "SELECT value FROM settings WHERE key='errors_dismissed_before_id'"
        ).fetchone()
        dismissed_before_id = int(dismissed_row["value"]) if dismissed_row else 0

        errors = conn.execute(
            "SELECT id,timestamp,sender,subject,action_taken "
            "FROM audit_log WHERE action_taken LIKE 'error%' AND id > ? ORDER BY id DESC LIMIT 5",
            (dismissed_before_id,),
        ).fetchall()

        conn.close()
    except sqlite3.OperationalError:
        pass  # DB doesn't exist yet

    # Service status
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "verdictmail"],
            capture_output=True, text=True, timeout=5
        )
        service_status = result.stdout.strip()
    except Exception:
        service_status = "unknown"

    # In signal-control environments the daemon stays "active" even when paused;
    # overlay the status so the dashboard shows the correct state.
    if service_status == "active" and PAUSE_FLAG.exists():
        service_status = "paused"

    return render_template(
        "dashboard.html",
        stats=stats,
        threat_counts=threat_counts,
        chart_labels=json.dumps(chart_labels),
        chart_pass=json.dumps(chart_pass),
        chart_flag=json.dumps(chart_flag),
        chart_junk=json.dumps(chart_junk),
        recent=recent,
        errors=errors,
        service_status=service_status,
        cfg=cfg,
    )


# ---------------------------------------------------------------------------
# Audit Log  GET /audit
# ---------------------------------------------------------------------------

@app.route("/audit")
@require_auth
def audit():
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    q = request.args.get("q", "").strip()
    threat_filter = request.args.get("threat", "").strip()
    action_filter = request.args.get("action", "").strip()

    where_clauses: list[str] = []
    params: list = []

    if q:
        where_clauses.append("(sender LIKE ? OR subject LIKE ? OR reasoning LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if threat_filter:
        where_clauses.append("threat_level = ?")
        params.append(threat_filter)
    if action_filter:
        where_clauses.append("action_taken = ?")
        params.append(action_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    rows: list[sqlite3.Row] = []
    total = 0

    try:
        conn = _db_conn()
        total = conn.execute(
            f"SELECT COUNT(*) FROM audit_log {where_sql}", params
        ).fetchone()[0]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT * FROM audit_log {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
        conn.close()
    except sqlite3.OperationalError:
        pass

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "audit.html",
        rows=rows,
        page=page,
        total_pages=total_pages,
        total=total,
        q=q,
        threat_filter=threat_filter,
        action_filter=action_filter,
    )


# ---------------------------------------------------------------------------
# Config editor  GET+POST /config
# ---------------------------------------------------------------------------

@app.route("/config", methods=["GET", "POST"])
@require_auth
def config_editor():
    if request.method == "POST":
        raw_yaml = request.form.get("yaml_content", "")
        try:
            parsed = yaml.safe_load(raw_yaml)
            if not isinstance(parsed, dict):
                raise ValueError("YAML must be a mapping")
            _save_config(parsed)
            flash("Configuration saved successfully.", "success")
        except Exception as exc:
            flash(f"Error saving config: {exc}", "danger")
        return redirect(url_for("config_editor"))

    with open(CONFIG_PATH) as f:
        yaml_content = f.read()

    cfg = _load_config()
    return render_template("config.html", yaml_content=yaml_content, cfg=cfg)


# ---------------------------------------------------------------------------
# Aggressiveness preset quick-config  POST /config/aggressiveness
# ---------------------------------------------------------------------------

_AGGRESSIVENESS_PRESETS = {
    "conservative":  {"flag": 0.75, "junk": 0.92},
    "default":       {"flag": 0.55, "junk": 0.80},
    "aggressive":    {"flag": 0.38, "junk": 0.65},
    "very_aggressive": {"flag": 0.22, "junk": 0.50},
}

@app.route("/config/aggressiveness", methods=["POST"])
@require_auth
def config_aggressiveness():
    preset = request.form.get("preset", "").strip().lower()
    if preset not in _AGGRESSIVENESS_PRESETS:
        flash(f"Unknown preset: {preset!r}", "danger")
        return redirect(url_for("config_editor"))
    try:
        cfg = _load_config()
        values = _AGGRESSIVENESS_PRESETS[preset]
        cfg.setdefault("thresholds", {})["flag"] = values["flag"]
        cfg["thresholds"]["junk"] = values["junk"]
        _save_config(cfg)
        label = preset.replace("_", " ").title()
        flash(
            f"Aggressiveness set to {label!r} "
            f"(flag ≥ {values['flag']}, junk ≥ {values['junk']}). "
            "Restart the daemon to apply.",
            "success",
        )
    except Exception as exc:
        flash(f"Error updating aggressiveness: {exc}", "danger")
    return redirect(url_for("config_editor"))


# ---------------------------------------------------------------------------
# AI provider quick-config  POST /config/ai
# ---------------------------------------------------------------------------

@app.route("/config/ai", methods=["POST"])
@require_auth
def config_ai():
    provider = request.form.get("ai_provider", "ollama").strip().lower()
    model = request.form.get("ai_model", "").strip()
    timeout = request.form.get("ai_timeout", "120").strip()
    ollama_base_url = request.form.get("ollama_base_url", "").strip()

    try:
        cfg = _load_config()
        cfg.pop("ollama", None)
        ai_section = cfg.setdefault("ai", {})
        ai_section["provider"] = provider
        if model:
            ai_section["model"] = model
        try:
            ai_section["timeout_seconds"] = int(timeout)
        except ValueError:
            pass
        if provider == "ollama" and ollama_base_url:
            ai_section["ollama_base_url"] = ollama_base_url
        _save_config(cfg)
        flash(f"AI provider set to '{provider}' (model: {ai_section.get('model', '?')}). Restart the daemon to apply.", "success")
    except Exception as exc:
        flash(f"Error updating AI config: {exc}", "danger")
    return redirect(url_for("config_editor"))


# ---------------------------------------------------------------------------
# Whitelist  GET /whitelist, POST /whitelist/add, POST /whitelist/delete/<idx>
# ---------------------------------------------------------------------------

@app.route("/whitelist", methods=["GET"])
@require_auth
def whitelist_view():
    cfg = _load_config()
    wl = cfg.get("whitelist", {})
    rules = wl.get("rules", [])
    enabled = wl.get("enabled", True)
    return render_template("whitelist.html", rules=rules, enabled=enabled)


@app.route("/whitelist/toggle", methods=["POST"])
@require_auth
def whitelist_toggle():
    cfg = _load_config()
    wl = cfg.setdefault("whitelist", {"enabled": True, "rules": []})
    wl["enabled"] = not wl.get("enabled", True)
    _save_config(cfg)
    state = "enabled" if wl["enabled"] else "disabled"
    flash(f"Whitelist {state}. Restart the daemon to apply.", "success")
    return redirect(url_for("whitelist_view"))


@app.route("/whitelist/add", methods=["POST"])
@require_auth
def whitelist_add():
    sender = request.form.get("sender", "").strip().lower()
    sender_domain = request.form.get("sender_domain", "").strip().lower()
    subject_contains = request.form.get("subject_contains", "").strip()
    comment = request.form.get("comment", "").strip()

    if not (sender or sender_domain or subject_contains):
        flash("At least one of Sender Email, Sender Domain, or Subject must be filled in.", "danger")
        return redirect(url_for("whitelist_view"))

    rule: dict = {}
    if sender:
        rule["sender"] = sender
    if sender_domain:
        rule["sender_domain"] = sender_domain
    if subject_contains:
        rule["subject_contains"] = subject_contains
    if comment:
        rule["comment"] = comment

    cfg = _load_config()
    wl = cfg.setdefault("whitelist", {"enabled": True, "rules": []})
    wl.setdefault("rules", []).append(rule)
    _save_config(cfg)
    flash("Whitelist rule added. Restart the daemon to apply.", "success")
    return redirect(url_for("whitelist_view"))


@app.route("/whitelist/edit/<int:idx>", methods=["POST"])
@require_auth
def whitelist_edit(idx):
    sender = request.form.get("sender", "").strip().lower()
    sender_domain = request.form.get("sender_domain", "").strip().lower()
    subject_contains = request.form.get("subject_contains", "").strip()
    comment = request.form.get("comment", "").strip()

    if not (sender or sender_domain or subject_contains):
        flash("At least one of Sender Email, Sender Domain, or Subject must be filled in.", "danger")
        return redirect(url_for("whitelist_view"))

    rule: dict = {}
    if sender:
        rule["sender"] = sender
    if sender_domain:
        rule["sender_domain"] = sender_domain
    if subject_contains:
        rule["subject_contains"] = subject_contains
    if comment:
        rule["comment"] = comment

    cfg = _load_config()
    rules = cfg.get("whitelist", {}).get("rules", [])
    if 0 <= idx < len(rules):
        rules[idx] = rule
        _save_config(cfg)
        flash("Whitelist rule updated. Restart the daemon to apply.", "success")
    else:
        flash("Rule not found.", "danger")
    return redirect(url_for("whitelist_view"))


@app.route("/whitelist/delete/<int:idx>", methods=["POST"])
@require_auth
def whitelist_delete(idx):
    cfg = _load_config()
    rules = cfg.get("whitelist", {}).get("rules", [])
    if 0 <= idx < len(rules):
        rules.pop(idx)
        _save_config(cfg)
        flash("Whitelist rule deleted. Restart the daemon to apply.", "success")
    else:
        flash("Rule not found.", "danger")
    return redirect(url_for("whitelist_view"))


# ---------------------------------------------------------------------------
# Credentials editor  GET+POST /credentials
# ---------------------------------------------------------------------------

@app.route("/credentials", methods=["GET", "POST"])
@require_auth
def credentials():
    if request.method == "POST":
        username = request.form.get("gmail_username", "").strip()
        password = request.form.get("gmail_app_password", "").strip()
        anthropic_key = request.form.get("anthropic_api_key", "").strip()
        openai_key = request.form.get("openai_api_key", "").strip()
        ollama_key = request.form.get("ollama_api_key", "").strip()
        urlhaus_key = request.form.get("urlhaus_api_key", "").strip()
        try:
            existing = dotenv_values(str(ENV_PATH)) if ENV_PATH.exists() else {}
            lines = [f"GMAIL_USERNAME={username}\n", f"GMAIL_APP_PASSWORD={password}\n"]
            for env_var, submitted in [
                ("ANTHROPIC_API_KEY", anthropic_key),
                ("OPENAI_API_KEY", openai_key),
                ("OLLAMA_API_KEY", ollama_key),
                ("URLHAUS_API_KEY", urlhaus_key),
            ]:
                value = submitted or existing.get(env_var, "")
                if value:
                    lines.append(f"{env_var}={value}\n")
            ENV_PATH.write_text("".join(lines))
            flash("Credentials saved. Restart the daemon for changes to take effect.", "success")
        except Exception as exc:
            flash(f"Error saving credentials: {exc}", "danger")
        return redirect(url_for("credentials"))

    creds = dotenv_values(str(ENV_PATH)) if ENV_PATH.exists() else {}
    return render_template("credentials.html", creds=creds)


# ---------------------------------------------------------------------------
# Change web UI password  POST /credentials/change-password
# ---------------------------------------------------------------------------

@app.route("/credentials/change-password", methods=["POST"])
@require_auth
def change_password():
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    try:
        cfg = _load_config()
        existing_hash = cfg.get("ui", {}).get("password_hash", "")
        if not check_password_hash(existing_hash, current):
            flash("Current password is incorrect.", "danger")
        elif len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "danger")
        elif new_pw != confirm:
            flash("New passwords do not match.", "danger")
        else:
            cfg.setdefault("ui", {})["password_hash"] = generate_password_hash(new_pw)
            _save_config(cfg)
            flash("Web UI password updated successfully.", "success")
    except Exception as exc:
        flash(f"Error changing password: {exc}", "danger")
    return redirect(url_for("credentials"))


# ---------------------------------------------------------------------------
# Manual Test  GET+POST /test
# ---------------------------------------------------------------------------

@app.route("/test", methods=["GET", "POST"])
@require_auth
def test():
    if request.method == "GET":
        return render_template("test.html")

    tab = request.form.get("tab", "simple")
    raw_bytes: bytes = b""

    if tab == "raw":
        raw_text = request.form.get("raw_rfc822", "")
        raw_bytes = raw_text.encode("latin-1", errors="replace")
    else:
        from_addr = request.form.get("from_addr", "test@example.com").strip()
        subject = request.form.get("subject", "(no subject)").strip()
        body = request.form.get("body", "").strip()
        originating_ip = request.form.get("originating_ip", "").strip()
        msg = email.mime.text.MIMEText(body, "plain", "utf-8")
        msg["From"] = from_addr
        msg["To"] = "sentinel@example.com"
        msg["Subject"] = subject
        msg["Message-ID"] = "<test@verdictmail>"
        msg["Date"] = "Mon, 01 Jan 2024 00:00:00 +0000"
        if originating_ip:
            import ipaddress as _ipaddress
            try:
                _ipaddress.IPv4Address(originating_ip)
                msg["Received"] = (
                    f"from mail.example.com ([{originating_ip}])"
                    f" by verdictmail-test.local with SMTP"
                )
            except ValueError:
                pass  # invalid IP — silently omit
        raw_bytes = msg.as_bytes()

    cfg = _load_config()
    ai_cfg = cfg.get("ai", cfg.get("ollama", {}))
    threshold_cfg = cfg.get("thresholds", {})
    dnsbl_lists = cfg.get("dnsbl", {}).get("lists", [])

    results: dict = {}
    error_msg: str | None = None

    try:
        from verdictmail.message_parser import parse_raw_message
        from verdictmail.enrichment import EnrichmentPipeline
        from verdictmail.ai_analyzer import AiAnalyzer
        from verdictmail.decision_engine import DecisionEngine
        from dotenv import dotenv_values as _dv

        parsed = parse_raw_message(raw_bytes)
        results["parsed"] = parsed

        # Whitelist check — mirrors the daemon's _match_whitelist logic
        whitelist_cfg = cfg.get("whitelist", {})
        whitelist_enabled = whitelist_cfg.get("enabled", True)
        whitelist_rules = whitelist_cfg.get("rules", []) if whitelist_enabled else []
        whitelist_match = None
        if whitelist_rules:
            _sender  = getattr(parsed, "sender_address", "") or ""
            _domain  = getattr(parsed, "sender_domain",  "") or ""
            _subject = (getattr(parsed, "subject", "") or "").lower()
            for _rule in whitelist_rules:
                _rs = (_rule.get("sender")           or "").lower()
                _rd = (_rule.get("sender_domain")    or "").lower()
                _rq = (_rule.get("subject_contains") or "").lower()
                if not (_rs or _rd or _rq):
                    continue
                if _rs and _rs != _sender:
                    continue
                if _rd and _rd != _domain:
                    continue
                if _rq and _rq not in _subject:
                    continue
                whitelist_match = _rule
                break

        if whitelist_match:
            results["whitelist_match"] = whitelist_match
        else:
            enriched = EnrichmentPipeline(dnsbl_lists).run(raw_bytes, parsed)
            results["enriched"] = enriched

        if not whitelist_match:
            ai_provider = ai_cfg.get("provider", "ollama")
            env_vals = _dv(str(ENV_PATH)) if ENV_PATH.exists() else {}
            if ai_provider == "anthropic":
                api_key = env_vals.get("ANTHROPIC_API_KEY", "")
            elif ai_provider == "openai":
                api_key = env_vals.get("OPENAI_API_KEY", "")
            else:
                api_key = env_vals.get("OLLAMA_API_KEY", "")

            ai = AiAnalyzer(
                provider=ai_provider,
                model=ai_cfg.get("model", "qwen2.5-coder:14b"),
                timeout_seconds=int(ai_cfg.get("timeout_seconds", 120)),
                base_url=ai_cfg.get("ollama_base_url", ai_cfg.get("base_url", "http://localhost:11434")),
                api_key=api_key,
            ).analyze(parsed, enriched)
            results["ai"] = ai

            decision = DecisionEngine(
                flag_threshold=float(threshold_cfg.get("flag", 0.55)),
                junk_threshold=float(threshold_cfg.get("junk", 0.80)),
            ).decide(ai)
            results["decision"] = decision

    except Exception as exc:
        error_msg = str(exc)

    return render_template("test.html", results=results, error_msg=error_msg, tab=tab)


# ---------------------------------------------------------------------------
# Service control  POST /service/restart|stop|start
# ---------------------------------------------------------------------------

# Control mode is detected once and cached for the process lifetime.
# "systemctl" — sudo + systemctl works (bare metal, privileged containers).
# "signal"     — sudo is unavailable (unprivileged LXC); uses SIGTERM + pause flag.
_CONTROL_MODE: str | None = None


def _get_control_mode() -> str:
    """Detect and cache whether sudo systemctl is usable in this environment.

    Uses `sudo -n -l` as a lightweight probe: sudo's privilege initialisation
    (GID change, audit plugin) runs before any command is executed, so this
    reliably fails in unprivileged LXC containers without actually touching
    the daemon.  Falls back to the signal/pause-flag strategy on any error.
    """
    global _CONTROL_MODE
    if _CONTROL_MODE is not None:
        return _CONTROL_MODE
    try:
        r = subprocess.run(
            ["sudo", "-n", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        bad = "unable to change" in r.stderr or "audit plugin" in r.stderr
        _CONTROL_MODE = "signal" if (bad or r.returncode != 0) else "systemctl"
    except Exception:
        _CONTROL_MODE = "signal"
    import logging
    logging.getLogger(__name__).info("Service control mode: %s", _CONTROL_MODE)
    return _CONTROL_MODE


def _systemctl(action: str) -> None:
    """Run a privileged systemctl action on verdictmail via sudo."""
    result = subprocess.run(
        ["sudo", "/usr/bin/systemctl", action, "verdictmail"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"systemctl {action} failed (rc={result.returncode})")


def _signal_restart() -> None:
    """Restart via SIGTERM — systemd respawns the daemon (Restart=always)."""
    result = subprocess.run(
        ["systemctl", "show", "verdictmail", "--property=MainPID", "--value"],
        capture_output=True, text=True, timeout=5,
    )
    pid = int(result.stdout.strip())
    if pid <= 1:
        raise RuntimeError("Daemon does not appear to be running (MainPID=0)")
    os.kill(pid, signal.SIGTERM)


@app.route("/service/restart", methods=["POST"])
@require_auth
def service_restart():
    try:
        if _get_control_mode() == "systemctl":
            _systemctl("restart")
        else:
            PAUSE_FLAG.unlink(missing_ok=True)
            _signal_restart()
        flash("Daemon restarting — it will be back in a few seconds.", "success")
    except Exception as exc:
        flash(f"Restart error: {exc}", "danger")
    next_url = request.form.get("next", "")
    return redirect(_safe_next_url(next_url, url_for("dashboard")))


@app.route("/service/stop", methods=["POST"])
@require_auth
def service_stop():
    try:
        if _get_control_mode() == "systemctl":
            _systemctl("stop")
            flash("Daemon stopped. Email monitoring is paused until you start it again.", "warning")
        else:
            PAUSE_FLAG.touch()
            flash("Daemon paused. Incoming emails will be held unread until you resume.", "warning")
    except Exception as exc:
        flash(f"Stop error: {exc}", "danger")
    return redirect(url_for("dashboard"))


@app.route("/service/start", methods=["POST"])
@require_auth
def service_start():
    try:
        if _get_control_mode() == "systemctl":
            _systemctl("start")
            flash("Daemon started. Email monitoring is now active.", "success")
        else:
            PAUSE_FLAG.unlink(missing_ok=True)
            flash("Daemon resumed. Email monitoring is now active.", "success")
    except Exception as exc:
        flash(f"Start error: {exc}", "danger")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Timezone quick-config  POST /config/timezone
# ---------------------------------------------------------------------------

@app.route("/config/timezone", methods=["POST"])
@require_auth
def config_timezone():
    tz_name = request.form.get("timezone", "UTC").strip()
    try:
        ZoneInfo(tz_name)  # validate
    except Exception:
        flash(f"Unknown timezone: {tz_name!r}. Use an IANA name like 'America/New_York'.", "danger")
        return redirect(url_for("config_editor"))
    try:
        cfg = _load_config()
        cfg["timezone"] = tz_name
        _save_config(cfg)
        flash(f"Timezone set to '{tz_name}'.", "success")
    except Exception as exc:
        flash(f"Error saving timezone: {exc}", "danger")
    return redirect(url_for("config_editor"))


# ---------------------------------------------------------------------------
# Clear audit log  POST /config/clear-logs
# ---------------------------------------------------------------------------

@app.route("/config/clear-logs", methods=["POST"])
@require_auth
def clear_logs():
    try:
        conn = _db_conn()
        conn.execute("DELETE FROM audit_log")
        conn.commit()
        conn.close()
        flash("Audit log cleared — all records deleted.", "success")
    except Exception as exc:
        flash(f"Error clearing logs: {exc}", "danger")
    return redirect(url_for("config_editor"))


# ---------------------------------------------------------------------------
# Dismiss recent errors  POST /dashboard/clear-errors
# ---------------------------------------------------------------------------

@app.route("/dashboard/clear-errors", methods=["POST"])
@require_auth
def clear_errors():
    try:
        conn = _db_conn()
        conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        max_row = conn.execute(
            "SELECT MAX(id) FROM audit_log WHERE action_taken LIKE 'error%'"
        ).fetchone()
        max_id = max_row[0] or 0
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('errors_dismissed_before_id', ?)",
            (str(max_id),),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Credential test endpoints  POST /credentials/test/*
# ---------------------------------------------------------------------------

@app.route("/credentials/test/gmail", methods=["POST"])
@require_auth
def test_gmail():
    username = request.json.get("username", "").strip()
    password = request.json.get("password", "").strip()
    cfg = _load_config()
    imap_cfg = cfg.get("imap", {})
    host = imap_cfg.get("host", "imap.gmail.com")
    port = imap_cfg.get("port", 993)
    if not username or not password:
        return jsonify(ok=False, msg="Username and password are required.")
    try:
        from imapclient import IMAPClient
        client = IMAPClient(host, port=port, ssl=True, use_uid=True)
        client.login(username, password)
        folders = client.list_folders()
        client.logout()
        return jsonify(ok=True, msg=f"Connected to {host} as {username}. {len(folders)} folder(s) found.")
    except Exception as exc:
        return jsonify(ok=False, msg=str(exc))


@app.route("/credentials/test/anthropic", methods=["POST"])
@require_auth
def test_anthropic():
    api_key = request.json.get("api_key", "").strip()
    if not api_key:
        return jsonify(ok=False, msg="API key is required.")
    try:
        import anthropic as anthropic_sdk
        client = anthropic_sdk.Anthropic(api_key=api_key)
        client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
        )
        return jsonify(ok=True, msg="Anthropic API key valid. Model responded successfully.")
    except Exception as exc:
        return jsonify(ok=False, msg=str(exc))


@app.route("/credentials/test/openai", methods=["POST"])
@require_auth
def test_openai():
    api_key = request.json.get("api_key", "").strip()
    if not api_key:
        return jsonify(ok=False, msg="API key is required.")
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
            max_tokens=16,
        )
        return jsonify(ok=True, msg="OpenAI API key valid. Model responded successfully.")
    except Exception as exc:
        return jsonify(ok=False, msg=str(exc))


@app.route("/credentials/test/ollama", methods=["POST"])
@require_auth
def test_ollama():
    cfg = _load_config()
    ai_cfg = cfg.get("ai", cfg.get("ollama", {}))
    base_url = ai_cfg.get("ollama_base_url", ai_cfg.get("base_url", "http://localhost:11434")).rstrip("/")
    api_key = request.json.get("api_key", "").strip()
    try:
        import httpx
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        resp = httpx.get(f"{base_url}/api/tags", headers=headers, timeout=8)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            model_str = ", ".join(models[:5]) or "(none)"
            return jsonify(ok=True, msg=f"Ollama reachable at {base_url}. Models: {model_str}")
        else:
            return jsonify(ok=False, msg=f"Ollama returned HTTP {resp.status_code}")
    except Exception as exc:
        return jsonify(ok=False, msg=str(exc))


@app.route("/credentials/test/urlhaus", methods=["POST"])
@require_auth
def test_urlhaus():
    api_key = request.json.get("api_key", "").strip()
    if not api_key:
        return jsonify(ok=False, msg="API key is required.")
    try:
        import requests as _requests
        resp = _requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": "https://example.com"},
            headers={"User-Agent": "VerdictMail/1.0", "Auth-Key": api_key},
            timeout=15,
        )
        data = resp.json()
        if "error" in data:
            return jsonify(ok=False, msg=f"URLhaus API returned: {data['error']}. Check that your key is correct.")
        return jsonify(ok=True, msg="URLhaus API key valid. Connection successful.")
    except _requests.exceptions.Timeout:
        return jsonify(ok=False, msg="Connection timed out. Verify your firewall allows outbound HTTPS to urlhaus-api.abuse.ch and try again.")
    except Exception as exc:
        return jsonify(ok=False, msg=str(exc))


# ---------------------------------------------------------------------------
# Ollama model list  GET /api/ollama-models
# ---------------------------------------------------------------------------

@app.route("/api/ollama-models")
@require_auth
def api_ollama_models():
    """Return the list of models available on the configured Ollama instance.

    Accepts an optional ?url= query param so the config page can pass whatever
    URL is currently typed in the form (before saving).
    """
    base_url = request.args.get("url", "").strip().rstrip("/")
    if base_url:
        _p = urlparse(base_url)
        if _p.scheme not in ("http", "https") or not _p.netloc:
            return jsonify(ok=False, models=[], msg="Invalid URL: must be http:// or https://")
    else:
        cfg = _load_config()
        ai_cfg = cfg.get("ai", cfg.get("ollama", {}))
        base_url = ai_cfg.get("ollama_base_url", "http://localhost:11434").rstrip("/")
    try:
        import httpx
        resp = httpx.get(f"{base_url}/api/tags", timeout=8)
        if resp.status_code == 200:
            models = sorted(m["name"] for m in resp.json().get("models", []))
            return jsonify(ok=True, models=models)
        return jsonify(ok=False, models=[], msg=f"Ollama returned HTTP {resp.status_code}")
    except Exception as exc:
        return jsonify(ok=False, models=[], msg=str(exc))


# ---------------------------------------------------------------------------
# Live status API  GET /api/status
# ---------------------------------------------------------------------------

@app.route("/api/status")
@require_auth
def api_status():
    # Scan log file in reverse to find the most recent IMAP status line
    log_path = Path("/var/log/verdictmail/verdictmail.log")
    imap_status = "unknown"
    connected_mailbox = "—"
    if log_path.exists():
        try:
            with open(log_path) as f:
                log_lines = [l.rstrip() for l in f]
        except Exception:
            log_lines = []
    else:
        log_lines = []

    for line in reversed(log_lines):
        if "IMAP connected" in line:
            imap_status = "connected"
            break
        if "Connecting to" in line and " as " in line:
            imap_status = "connecting"
            break
        if "Reconnecting in" in line:
            imap_status = "reconnecting"
            break
        if "IMAP error" in line or "Failed to reconnect" in line:
            imap_status = "error"
            break

    # Configured mailbox from .env
    try:
        env_vals = dotenv_values(str(ENV_PATH)) if ENV_PATH.exists() else {}
        connected_mailbox = env_vals.get("GMAIL_USERNAME", "—")
    except Exception:
        pass

    # Most recent audit log entry
    last_email = None
    try:
        conn = _db_conn()
        row = conn.execute(
            "SELECT timestamp, sender, subject, threat_level, action_taken, processing_ms "
            "FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            last_email = dict(row)
        conn.close()
    except Exception:
        pass

    # Daemon systemd state
    daemon_active = False
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "verdictmail"],
            capture_output=True, text=True, timeout=3,
        )
        daemon_active = result.stdout.strip() == "active"
    except Exception:
        pass

    cfg = _load_config()
    tz = _get_tz(cfg)

    # Convert last_email timestamp to local time for display
    if last_email and last_email.get("timestamp"):
        try:
            dt = datetime.fromisoformat(last_email["timestamp"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            last_email["timestamp_local"] = dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        except Exception:
            last_email["timestamp_local"] = last_email["timestamp"][:16]

    return jsonify(
        log_lines=log_lines[-40:],
        imap_status=imap_status,
        mailbox=connected_mailbox,
        last_email=last_email,
        daemon_active=daemon_active,
    )


# ---------------------------------------------------------------------------
# Documentation  GET /docs
# ---------------------------------------------------------------------------

@app.route("/docs")
@require_auth
def docs():
    return render_template("docs.html")


# ---------------------------------------------------------------------------
# About  GET /about
# ---------------------------------------------------------------------------

@app.route("/about")
@require_auth
def about():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
