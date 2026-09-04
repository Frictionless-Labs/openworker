"""Durable local audit log for connector/tool actions."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

from .connectors import connector_for_tool
from .trust import looks_like_secret

_SECRET_KEYS = (
    "token",
    "secret",
    "password",
    "api_key",
    "access_token",
    "bot_token",
    "app_token",
    "raw",
)
_BODY_KEYS = ("body", "content", "html")


class AuditStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path).expanduser()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT,
                agent TEXT,
                workspace TEXT,
                connector TEXT,
                tool TEXT,
                stage TEXT,
                status TEXT,
                approval TEXT,
                args TEXT,
                result_preview TEXT,
                reason TEXT,
                resource TEXT,
                call_id TEXT,
                tokens_in INTEGER DEFAULT 0,
                tokens_out INTEGER DEFAULT 0,
                cache_read INTEGER DEFAULT 0,
                cache_write INTEGER DEFAULT 0
            )
            """)
        # Existing databases predate the reviewer columns (2026-08-12): call_id joins a
        # shadow verdict to the human's decision on the same tool call, tokens_in/out are
        # the reviewer metering (§1.7). ALTER is idempotent-by-error: "duplicate column"
        # means an already-migrated file.
        for column, decl in (
            ("call_id", "TEXT"),
            ("tokens_in", "INTEGER DEFAULT 0"),
            ("tokens_out", "INTEGER DEFAULT 0"),
            # Cached-prefix share of a reviewer check (2026-08-22). Without these the
            # metering badge could only ever see the FRESH tokens — ~75 of a ~1,500-token
            # check once the provider caches the instruction prefix — so it under-reported
            # cost by more the longer a session ran. Same defect class as OPE-101, one
            # layer further out.
            ("cache_read", "INTEGER DEFAULT 0"),
            ("cache_write", "INTEGER DEFAULT 0"),
        ):
            try:
                self._conn.execute(
                    f"ALTER TABLE audit_events ADD COLUMN {column} {decl}"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
        self._conn.commit()

    def append(self, event: dict[str, Any]) -> None:
        tool = str(event.get("tool") or event.get("tool_name") or "")
        connector = str(event.get("connector") or connector_for_tool(tool) or "")
        args = _sanitize_args(tool, event.get("arguments") or {})
        resource = _resource(
            tool, event.get("arguments") or {}, event.get("result") or {}
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_events
                    (session_id, agent, workspace, connector, tool, stage, status, approval, args, result_preview, reason, resource, call_id, tokens_in, tokens_out, cache_read, cache_write)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("session_id") or "",
                    event.get("agent") or "",
                    event.get("workspace") or "",
                    connector,
                    tool,
                    event.get("stage") or "",
                    event.get("status") or "",
                    event.get("approval") or "",
                    json.dumps(args, default=str),
                    _sanitized_preview(
                        event.get("result"), event.get("result_preview")
                    ),
                    _truncate(str(event.get("reason") or "")),
                    _truncate(str(resource or "")),
                    str(event.get("call_id") or ""),
                    int(event.get("tokens_in") or 0),
                    int(event.get("tokens_out") or 0),
                    int(event.get("cache_read") or 0),
                    int(event.get("cache_write") or 0),
                ),
            )
            self._conn.commit()

    def reviewer_stats(self, session_id: str) -> dict[str, Any]:
        """Per-session Auto-Approve metering (§1.7), computed from the durable rows so it
        survives restarts and engine rebuilds. `live` counts stage=reviewer_verdict (the
        mode actually deciding); `shadow` counts stage=reviewer_shadow (recording only)."""

        def _bucket(stage: str) -> dict[str, int]:
            with self._lock:
                rows = self._conn.execute(
                    """
                    SELECT status, COUNT(*) AS n,
                           COALESCE(SUM(tokens_in), 0) AS tin,
                           COALESCE(SUM(tokens_out), 0) AS tout,
                           COALESCE(SUM(cache_read), 0) AS cread,
                           COALESCE(SUM(cache_write), 0) AS cwrite
                    FROM audit_events
                    WHERE session_id = ? AND stage = ?
                    GROUP BY status
                    """,
                    (session_id, stage),
                ).fetchall()
            out = {
                "checks": 0, "allow": 0, "deny": 0, "unsure": 0,
                "tokens_in": 0, "tokens_out": 0, "cache_read": 0, "cache_write": 0,
            }
            for row in rows:
                status = str(row["status"])
                if status in ("allow", "deny", "unsure"):
                    out[status] += int(row["n"])
                out["checks"] += int(row["n"])
                out["tokens_in"] += int(row["tin"])
                out["tokens_out"] += int(row["tout"])
                out["cache_read"] += int(row["cread"])
                out["cache_write"] += int(row["cwrite"])
            return out

        return {"live": _bucket("reviewer_verdict"), "shadow": _bucket("reviewer_shadow")}

    def list(
        self,
        *,
        limit: int = 100,
        session_id: Optional[str] = None,
        connector: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        where = []
        params: list[Any] = []
        if session_id:
            where.append("session_id = ?")
            params.append(session_id)
        if connector:
            where.append("connector = ?")
            params.append(connector)
        if tool:
            where.append("tool = ?")
            params.append(tool)
        sql = "SELECT * FROM audit_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(int(limit or 100), 500)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["args"] = json.loads(item.get("args") or "{}")
            except json.JSONDecodeError:
                item["args"] = {}
            out.append(item)
        return out

    def close(self) -> None:
        self._conn.close()


def _sanitize_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(args, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in args.items():
        lk = str(key).lower()
        if any(s in lk for s in _SECRET_KEYS):
            out[key] = "[redacted]"
        elif tool == "browser_type" and lk == "text":
            out[key] = "[redacted input]"
        elif any(b == lk or lk.endswith("_" + b) for b in _BODY_KEYS):
            out[key] = "[redacted body]"
        else:
            out[key] = _summarize(value)
    return out


def _summarize(value: Any) -> Any:
    if isinstance(value, str):
        return _truncate(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_summarize(v) for v in value[:10]]
    if isinstance(value, dict):
        return {str(k): _summarize(v) for k, v in list(value.items())[:20]}
    return _truncate(str(value))


# Keys whose VALUE is bulk content rather than an identifier. An email body, a fetched
# page, a file's text: useful to the agent in the moment, and a durable copy of someone's
# correspondence once it lands in SQLite. The audit trail exists to explain WHO authorised
# WHAT — not to become a second, unencrypted store of the things the agent read.
_RESULT_BODY_KEYS = (
    "body",
    "content",
    "html",
    "text",
    "snippet",
    "preview",
    "message",
    "value",
    "env",
    "environ",
    "environment",
)

# Keys that identify the action. Kept verbatim so a row still answers "which resource?"
# even when everything around it is redacted.
_RESULT_KEEP_KEYS = (
    "id",
    "url",
    "path",
    "status",
    "ok",
    "error",
    "count",
    "name",
    "subject",
    "from",
    "to",
    "tool",
    "kind",
)

_REDACTED = "[redacted]"
_REDACTED_BODY = "[redacted body]"


def _redact_result(value: Any, key: str = "", depth: int = 0) -> Any:
    """Redact secret- and body-shaped fields from a structured tool result (OW-SEC-015).

    Runs BEFORE flattening and truncating, because truncation is not redaction: a 500-char
    prefix of an email body is still an email body, and a token shorter than the limit
    survives it whole.

    Structure is preserved — keys, shapes, list lengths — so a row still shows what came
    back. Only the values that carry content or credentials are replaced.
    """
    if depth > 8:
        return _REDACTED
    lk = str(key).lower()
    if lk and any(sk in lk for sk in _SECRET_KEYS):
        return _REDACTED
    if lk and lk not in _RESULT_KEEP_KEYS and any(
        b == lk or lk.endswith("_" + b) for b in _RESULT_BODY_KEYS
    ):
        return _REDACTED_BODY
    if isinstance(value, dict):
        return {
            str(k): _redact_result(v, str(k), depth + 1) for k, v in list(value.items())[:40]
        }
    if isinstance(value, (list, tuple)):
        return [_redact_result(v, key, depth + 1) for v in list(value)[:20]]
    if isinstance(value, str):
        return _REDACTED if looks_like_secret(value) else value
    return value


def _sanitized_preview(result: Any, fallback: Any) -> str:
    """The durable `result_preview` column: redacted, then flattened, then truncated.

    When the caller supplied no structured result there is nothing to walk, so the
    pre-flattened string is scanned for credential literals and kept otherwise — the
    conservative half of the same rule.
    """
    if isinstance(result, (dict, list, tuple)):
        redacted = _redact_result(result)
        try:
            text = json.dumps(redacted, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(redacted)
        return _truncate(text)
    if isinstance(result, str) and result:
        return _truncate(_REDACTED if looks_like_secret(result) else result)
    raw = str(fallback or "")
    return _truncate(_REDACTED if looks_like_secret(raw) else raw)


def _resource(tool: str, args: dict[str, Any], result: Any) -> str:
    for key in (
        "url",
        "owner",
        "repo",
        "issue_key",
        "page_id",
        "ticket_id",
        "calendar_id",
        "message_id",
    ):
        if isinstance(args, dict) and args.get(key):
            return str(args[key])
    if isinstance(args, dict) and args.get("subdomain"):
        return f"{args['subdomain']}.zendesk.com"
    if isinstance(result, dict) and result.get("url"):
        return str(result["url"])
    return ""


def _truncate(text: str, limit: int = 500) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."
