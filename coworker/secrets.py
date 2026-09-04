"""Secret store — one canonical, file-backed store for connector/MCP credentials.

Design (from OpenClaw): secrets **never enter the model's context, prompts, or traces**.
The store holds profiles keyed by `connector[:account]`; values may be literals OR
`${ENV_VAR}` references resolved at read time from the process env / `~/.config/coworker/.env`.

v1 is a `0600` JSON file behind this interface; the interface is what callers depend on, so
a Keychain / age-encrypted backend can swap in later without touching them.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_IS_WINDOWS = sys.platform == "win32"


def state_dir() -> Path:
    """Where coworker keeps its state — the one cross-platform source of truth.

    Resolution order:
    1. `$COWORKER_STATE_DIR` — explicit override on any OS (used by tests/sidecars).
    2. Windows: `%APPDATA%\\coworker` (e.g. `C:\\Users\\You\\AppData\\Roaming\\coworker`),
       the native per-user app-data location.
    3. macOS / Linux: `~/.config/coworker` (XDG-style, unchanged from prior behavior).
    """
    base = os.environ.get("COWORKER_STATE_DIR")
    if base:
        return Path(base).expanduser()
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "coworker"
    return Path.home() / ".config" / "coworker"


def _load_dotenv(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _restrict_to_user(path: Path, *, is_dir: bool) -> None:
    """Restrict a path so only the current user can access it.

    POSIX expresses this with mode bits (0700 dir / 0600 file). Windows has no such bits —
    `os.chmod` there only toggles the read-only flag, so a 0600 chmod is a silent no-op and
    the file inherits broad ACLs (SYSTEM, Administrators, …). Use an ACL instead: strip
    inherited entries and grant the current user alone. Best-effort on Windows so a transient
    icacls failure never blocks saving a key."""
    if _IS_WINDOWS:
        user = os.environ.get("USERNAME")
        if not user:
            return
        domain = os.environ.get("USERDOMAIN")
        account = f"{domain}\\{user}" if domain else user
        # A directory grant MUST be inheritable — (OI) object-inherit for files, (CI)
        # container-inherit for subdirs — so everything created inside (the SQLite stores,
        # conversations, …) inherits the user's access. Without these flags, /inheritance:r
        # leaves the directory with a non-inheritable ACE and any child file ends up with an
        # empty DACL → sqlite3 "unable to open database file", crashing the server on launch.
        grant = f"{account}:(OI)(CI)F" if is_dir else f"{account}:F"
        try:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
                capture_output=True,
                check=False,
            )
        except OSError:
            pass
        return
    os.chmod(path, 0o700 if is_dir else 0o600)


def _atomic_private_write(target: Path, content: str) -> Path:
    """Write `content` to `target` atomically, never exposing it through a readable temp.

    The temp file used to be created by `Path.write_text` and only chmod-ed afterwards, so
    the plaintext sat on disk at the umask default (0644 on a normal box) for the length of
    the write — readable by every local process and by anything backing the directory up.
    That is issue #143; the same pattern was in both writers here.

    `tempfile.mkstemp` creates with 0600 and O_EXCL before a byte is written, which also
    removes the fixed `<name>.tmp` filename. That name was predictable, so a local attacker
    could pre-create it as a symlink and have the write land wherever the link pointed.

    Windows gets no mode bits from mkstemp, so the ACL is applied to the still-empty file
    before the content goes in.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        _restrict_to_user(target.parent, is_dir=True)
    except OSError:
        pass

    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        _restrict_to_user(tmp, is_dir=False)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    return target


def write_private_text(path: str | Path, content: str) -> Path:
    """Atomically write a user-only text file using the SecretStore's OS protections."""
    return _atomic_private_write(Path(path).expanduser(), content)


# -- storage backends (OWH M07 / OW-SEC-016) ------------------------------------
#
# The interface above is what every caller depends on; where the bytes actually live is
# this layer's business. v1 was a `0600` JSON file, whose own docstring anticipated the
# swap: "a Keychain / age-encrypted backend can swap in later without touching them."
#
# File permissions are not encryption. `0600` stops another *user* on the machine; it does
# nothing about malware running as the operator, a backup that copies the file, or anyone
# who gets the disk. The native credential store is the control that addresses those.


class FileBackend:
    """The v1 store: one `0600` JSON file. Still the backend everywhere the native store
    is unavailable, and still the migration source."""

    name = "file"

    def __init__(self, path: Path) -> None:
        self.path = path

    def available(self) -> bool:
        return True

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def save(self, store: dict[str, Any]) -> None:
        _atomic_private_write(self.path, json.dumps(store, indent=2))


class KeychainBackend:
    """macOS Keychain, through the `security` CLI that ships with the OS.

    The whole profile map is one generic-password item rather than one item per profile.
    That keeps the store atomic — a partial write cannot leave half the profiles from one
    version and half from another — and it keeps the number of keychain prompts at one.

    The CLI is used deliberately in preference to a binding library: no new dependency
    enters the release graph for a launch-platform feature, and `security` is present on
    every supported macOS.
    """

    name = "keychain"
    SERVICE = "com.openworker.secrets"

    def __init__(self, account: str = "default") -> None:
        self.account = account

    def available(self) -> bool:
        if sys.platform != "darwin":
            return False
        try:
            proc = subprocess.run(
                ["security", "-h"], capture_output=True, timeout=5, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode in (0, 1)

    def load(self) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                [
                    "security", "find-generic-password",
                    "-s", self.SERVICE, "-a", self.account, "-w",
                ],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"keychain read failed: {exc}") from exc
        if proc.returncode != 0:
            # 44 = item not found, which is an empty store, not a failure.
            if "could not be found" in (proc.stderr or ""):
                return {}
            raise RuntimeError(f"keychain read failed: {(proc.stderr or '').strip()}")
        raw = (proc.stdout or "").strip()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("keychain item is not valid JSON") from exc

    def save(self, store: dict[str, Any]) -> None:
        payload = json.dumps(store)
        try:
            proc = subprocess.run(
                [
                    "security", "add-generic-password",
                    "-s", self.SERVICE, "-a", self.account,
                    "-w", payload,
                    "-U",  # update in place when the item already exists
                ],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"keychain write failed: {exc}") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"keychain write failed: {(proc.stderr or '').strip()}")


def default_backend(path: Path) -> Any:
    """The native store on the launch platform, else the file store.

    Never raises: an unavailable keychain degrades to the previous behaviour rather than
    leaving the app without credentials. The consequence is recorded, not hidden — the
    high-sensitivity capability gate reads `SecretStore.backend_name`.
    """
    keychain = KeychainBackend()
    try:
        if keychain.available():
            return keychain
    except Exception:
        pass
    return FileBackend(path)


class MigrationError(RuntimeError):
    """Raised when a credential migration could not be verified. The legacy copy is always
    still present when this is raised — that is the point of it."""


class SecretStore:
    """File-backed secret store. Reads resolve `${VAR}` refs; status never leaks values."""

    def __init__(
        self, path: Optional[str | Path] = None, *, backend: Optional[Any] = None
    ) -> None:
        self.path = Path(path).expanduser() if path else state_dir() / "secrets.json"
        self._dotenv_path = self.path.parent / ".env"
        self._lock = threading.Lock()
        self._backend = backend if backend is not None else default_backend(self.path)
        # A native-store read is a subprocess, so the map is cached and invalidated on our
        # own writes. An out-of-band edit to the store is therefore not seen until restart —
        # true of the file backend's own callers as well, and the store is not a shared
        # mutable surface.
        self._cache: Optional[dict[str, Any]] = None

    @property
    def backend_name(self) -> str:
        """Which store the credentials actually live in. Release evidence records this: a
        pilot running on the file backend has NOT met the native-storage gate."""
        return getattr(self._backend, "name", "unknown")

    # -- reads ------------------------------------------------------------------
    def get(self, profile: str) -> Optional[dict[str, Any]]:
        """Return a profile with `${VAR}` refs resolved, or None if absent."""
        data = self._read().get(profile)
        if data is None:
            return None
        return self.resolve(data)

    def resolve(self, value: Any) -> Any:
        """Resolve `${VAR}` refs in a value (recursively) from env + the local `.env`."""
        env = _load_dotenv(self._dotenv_path)

        def _walk(v: Any) -> Any:
            if isinstance(v, str):
                return _REF.sub(
                    lambda m: os.environ.get(m.group(1))
                    or env.get(m.group(1))
                    or m.group(0),
                    v,
                )
            if isinstance(v, dict):
                return {k: _walk(x) for k, x in v.items()}
            if isinstance(v, list):
                return [_walk(x) for x in v]
            return v

        return _walk(value)

    def status(self) -> list[dict[str, Any]]:
        """Profile metadata only — **never** the secret values themselves."""
        out: list[dict[str, Any]] = []
        for profile, data in self._read().items():
            data = data if isinstance(data, dict) else {}
            expires = data.get("expires")
            expired = isinstance(expires, (int, float)) and expires < time.time()
            out.append(
                {
                    "profile": profile,
                    "type": data.get("type"),
                    "account": data.get("account_id"),
                    "expired": bool(expired),
                }
            )
        return out

    # -- writes -----------------------------------------------------------------
    def put(self, profile: str, data: dict[str, Any]) -> None:
        with self._lock:
            store = self._read()
            store[profile] = data
            self._write(store)

    def delete(self, profile: str) -> bool:
        with self._lock:
            store = self._read()
            if profile not in store:
                return False
            del store[profile]
            self._write(store)
            return True

    # -- migration --------------------------------------------------------------
    def migrate_to_backend(self) -> dict[str, Any]:
        """Move the legacy file store into the active backend, transactionally.

        The ordering is the whole control (OW-SEC-016): write, **verify by reading back**,
        and only then retire the legacy file — by RENAMING it, never by deleting it. At no
        point does exactly one copy of a credential exist. A read-back mismatch, or any
        backend error, raises `MigrationError` with the legacy file untouched, so the
        rollback is "do nothing".

        Returns a summary safe to log: counts and the backend name, never a value.
        """
        result = {
            "backend": self.backend_name,
            "migrated": 0,
            "status": "skipped",
            "legacy_file": str(self.path),
        }
        if self.backend_name == "file":
            result["status"] = "not-applicable"
            return result
        legacy = FileBackend(self.path)
        pending = legacy.load()
        if not pending:
            result["status"] = "nothing-to-migrate"
            return result

        existing = self._backend.load()
        merged = {**pending, **existing}  # anything already native wins; never clobber
        try:
            self._backend.save(merged)
        except Exception as exc:
            raise MigrationError(f"could not write to {self.backend_name}: {exc}") from exc

        try:
            readback = self._backend.load()
        except Exception as exc:
            raise MigrationError(
                f"could not read back from {self.backend_name}: {exc}"
            ) from exc
        missing = [p for p in pending if readback.get(p) != merged.get(p)]
        if missing:
            raise MigrationError(
                f"{len(missing)} profile(s) did not read back identically from "
                f"{self.backend_name}; the legacy store has been left in place"
            )

        # Verified. Only now does the legacy file stop being the live copy — and it is
        # retired by rename, so a later problem is still recoverable by hand.
        retired = self.path.with_name(self.path.name + f".migrated-{int(time.time())}")
        try:
            self.path.replace(retired)
        except OSError as exc:
            raise MigrationError(f"could not retire the legacy store: {exc}") from exc
        self._cache = None
        result.update(
            migrated=len(pending), status="migrated", retired_to=str(retired)
        )
        return result

    # -- internals --------------------------------------------------------------
    def _read(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        try:
            store = self._backend.load()
        except Exception:
            # A backend that cannot be read must not look like an empty store to a caller
            # that would then overwrite it. Fall back to the legacy file if it survives,
            # else raise — losing credentials silently is worse than failing loudly.
            legacy = FileBackend(self.path).load()
            if legacy:
                return legacy
            raise
        self._cache = store
        return store

    def _write(self, store: dict[str, Any]) -> None:
        self._backend.save(store)
        self._cache = dict(store)
