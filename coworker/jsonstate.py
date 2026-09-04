"""Guarded, atomic JSON state (OWH M09 / OW-REL-001).

Small JSON files hold a surprising amount of the operator's world: the inbox queue, channel
subscriptions, unattended settings, risk overrides. At the baseline most of them were read
with a bare `json.loads` and written with `write_text`, which gives two failure modes:

* **A truncated file bricks startup.** `write_text` is not atomic — a crash, a full disk, or
  a killed process mid-write leaves a half file, and the next `json.loads` raises out of a
  constructor that runs during server boot. One corrupt store then takes the whole app down,
  including the parts that would have let the operator fix it.
* **Recovery destroys the evidence.** The obvious repair — catch the error and start empty —
  silently overwrites whatever was left, so nobody can tell afterwards whether it was a
  crash or something worth investigating.

The primitives here fix both: writes land atomically, and an unreadable file is *quarantined*
(renamed, never deleted) before the store falls back to its default. Recovery is logged with
the store name and the reason — never the content, which is exactly the material that would
make a log a second copy of the thing it is reporting on.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RecoveryEvent:
    """One store that could not be read, and where its remains were put."""

    store: str
    reason: str
    quarantine_ref: str
    timestamp: str


# Set by the server so recoveries surface somewhere a person looks. Kept as a module-level
# hook rather than a constructor argument so migrating a store needs no signature change.
_recovery_sink: Optional[Callable[[RecoveryEvent], None]] = None


def set_recovery_sink(sink: Optional[Callable[[RecoveryEvent], None]]) -> None:
    global _recovery_sink
    _recovery_sink = sink


def _emit(event: RecoveryEvent) -> None:
    logger.warning(
        "recovered %s: %s (quarantined to %s)",
        event.store,
        event.reason,
        event.quarantine_ref or "(nothing to keep)",
    )
    if _recovery_sink is not None:
        try:
            _recovery_sink(event)
        except Exception:  # a broken sink must not become a broken startup
            logger.debug("recovery sink failed", exc_info=True)


def quarantine(path: Path, reason: str) -> str:
    """Move an unreadable file aside and return where it went (`""` if it could not be).

    Renamed, never deleted: the bad bytes are the only evidence of what happened, and a
    disk-full truncation and a tampered file look identical once they are gone.
    """
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    target = path.with_name(f"{path.name}.corrupt-{stamp}")
    try:
        path.replace(target)
        return str(target)
    except OSError:
        logger.debug("could not quarantine %s", path, exc_info=True)
        return ""


def read_json_safe(
    path: str | Path,
    *,
    default: Any = None,
    store: str = "",
    expect: Any = dict,
) -> Any:
    """Load JSON, or fall back to `default` after quarantining an unreadable file.

    Returns `default` for a MISSING file without quarantining anything — absent is a normal
    first-run state, not a corruption. An empty file is treated as corrupt: something wrote
    it and produced nothing, which is the interrupted-write signature.

    `expect` is the shape the caller can actually use, and it is checked here rather than
    left to each caller because "parses as JSON" is not the same as "is loadable". A file
    containing `"items"` is valid JSON and a valid *string*, and every store in this
    codebase would then call `.get` on it and raise out of a boot-time constructor — the
    exact failure this module exists to prevent. Pass `expect=None` to accept any value.
    """
    p = Path(path)
    name = store or p.name
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default() if callable(default) else default
    except OSError as exc:
        _emit(
            RecoveryEvent(name, f"unreadable: {type(exc).__name__}", "", _now())
        )
        return default() if callable(default) else default

    if not raw.strip():
        ref = quarantine(p, "empty file")
        _emit(RecoveryEvent(name, "empty file (interrupted write)", ref, _now()))
        return default() if callable(default) else default

    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # The message names the position, never the content around it.
        reason = f"invalid JSON: {type(exc).__name__}"
        ref = quarantine(p, reason)
        _emit(RecoveryEvent(name, reason, ref, _now()))
        return default() if callable(default) else default

    if expect is not None and not isinstance(value, expect):
        reason = f"unexpected shape: {type(value).__name__}"
        ref = quarantine(p, reason)
        _emit(RecoveryEvent(name, reason, ref, _now()))
        return default() if callable(default) else default
    return value


def write_json_atomic(
    path: str | Path, data: Any, *, indent: Optional[int] = 2
) -> Path:
    """Serialize and replace `path` atomically.

    Temp file in the SAME directory (so the replace is a rename within one filesystem),
    flushed and fsynced before it is put in place, then the directory entry is fsynced so
    the rename itself survives a power loss. A reader therefore sees either the whole old
    file or the whole new one — never the half-written state the previous `write_text`
    could leave behind.

    Serialization happens BEFORE the temp file is opened: a value that cannot be encoded
    raises without having touched anything on disk.
    """
    p = Path(path)
    payload = json.dumps(data, indent=indent, default=str)
    p.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(p)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_dir(p.parent)
    return p


def _fsync_dir(directory: Path) -> None:
    """Best-effort: not every platform allows opening a directory (Windows does not), and a
    durability gap is not worth failing a write over."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
