"""M06 files + shell confinement corpus (OW-SEC-011/012/013/014).

The invariant: **an alternate tool cannot reach a location the canonical file tools would
refuse.** Two ways that breaks — a path that escapes the granted roots, and an allowlist
entry on a program that runs code chosen somewhere else — and both are covered here, each
paired with the legitimate case it must not break.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from coworker.conversations import is_safe_session_id
from coworker.permissions import Decision, Mode, PermissionEngine, _path_operands
from coworker.roots import RootDir


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "workspace"
    (ws / "sub").mkdir(parents=True)
    (ws / "notes.txt").write_text("hi")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secrets.txt").write_text("shh")
    second = tmp_path / "second"
    second.mkdir()
    (second / "readme.md").write_text("ok")
    return ws, outside, second


def _engine(workspace, *, allowed_commands=(), extra_roots=(), mode=Mode.INTERACTIVE):
    ws = workspace[0]
    roots = [RootDir(path=ws, writable=True), *extra_roots]
    return PermissionEngine(
        workspace_root=ws,
        mode=mode,
        allowed_commands=list(allowed_commands),
        roots=roots,
    )


# -- 1. Path operand extraction -------------------------------------------------

OPERANDS = [
    ("plain relative", "cat sub/notes.txt", ["sub/notes.txt"]),
    ("home expansion", "cat ~/.aws/credentials", ["~/.aws/credentials"]),
    ("relative traversal", "cat ../../etc/passwd", ["../../etc/passwd"]),
    ("windows traversal", r"cat ..\..\etc\passwd", ["../../etc/passwd"]),
    ("option-embedded path", "grep --file=../../secrets.txt x", ["../../secrets.txt"]),
    ("absolute", "cat /etc/shadow", ["/etc/shadow"]),
    ("no operands", "git status -s", []),
    ("url is a destination, not a path", "curl https://x.test/a/b", []),
    ("bare word is not a path", "ls foo", []),
]


@pytest.mark.parametrize("label,command,expected", OPERANDS, ids=[r[0] for r in OPERANDS])
def test_path_operands(label, command, expected):
    got = _path_operands(command)
    for want in expected:
        assert want in got, f"{label}: expected {want} among {got}"
    if not expected:
        assert got == [], f"{label}: expected no operands, got {got}"


# -- 2. Shell paths cannot escape granted roots ---------------------------------

ESCAPES = [
    ("home directory read", "cat ~/.aws/credentials"),
    ("relative traversal", "cat ../outside/secrets.txt"),
    ("absolute outside", "cat /etc/shadow"),
    ("windows separator traversal", r"cat ..\outside\secrets.txt"),
    ("option-embedded escape", "grep --file=/etc/shadow pattern"),
    ("escape in the second half of a chain", "cat notes.txt && cat /etc/shadow"),
]


@pytest.mark.parametrize("label,command", ESCAPES, ids=[r[0] for r in ESCAPES])
def test_allowlisted_command_cannot_read_outside_the_roots(workspace, label, command):
    """An allowlist entry vets what a command DOES; the roots vet what it TOUCHES."""
    eng = _engine(workspace, allowed_commands=["cat", "grep"])
    d = eng.evaluate("run_shell", {"command": command})
    assert d.allowed is False, label
    assert d.needs_user is True, f"{label}: must reach a person, not hard-deny"


BENIGN_SHELL = [
    ("in-root relative", "cat notes.txt"),
    ("in-root subdirectory", "cat sub/../notes.txt"),
    ("no path operand at all", "git status -s"),
    ("chained in-root reads", "cat notes.txt && cat sub/../notes.txt"),
]


@pytest.mark.parametrize("label,command", BENIGN_SHELL, ids=[r[0] for r in BENIGN_SHELL])
def test_in_root_allowlisted_commands_still_auto_run(workspace, label, command):
    eng = _engine(workspace, allowed_commands=["cat", "git status"])
    assert eng.evaluate("run_shell", {"command": command}).allowed is True, label


def test_a_second_granted_root_is_reachable(workspace):
    ws, _outside, second = workspace
    eng = _engine(workspace, allowed_commands=["cat"], extra_roots=[RootDir(path=second)])
    assert eng.evaluate("run_shell", {"command": f"cat {second / 'readme.md'}"}).allowed is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlink_pointing_out_of_the_root_does_not_escape(workspace):
    """Root checks resolve symlinks, so a link planted inside the workspace cannot be used
    as a door out of it."""
    ws, outside, _second = workspace
    link = ws / "door"
    link.symlink_to(outside)
    eng = _engine(workspace, allowed_commands=["cat"])
    assert eng.evaluate("run_shell", {"command": "cat door/secrets.txt"}).allowed is False
    assert eng.evaluate("write_file", {"path": str(link / "x.txt"), "content": "y"}).allowed is False


# -- 3. Delegating programs never auto-run from a bare allowlist entry ----------

DANGEROUS_BARE = [
    ("interpreter runs a script file", ["python"], "python attacker.py"),
    ("interpreter, node", ["node"], "node payload.js"),
    ("interpreter, ruby", ["ruby"], "ruby payload.rb"),
    ("shell interpreter", ["bash"], "bash setup.sh"),
    ("package manager install", ["npm"], "npm install evil-package"),
    ("package manager arbitrary script", ["npm"], "npm run whatever"),
    ("pip install", ["pip"], "pip install evil"),
    ("build tool reads a recipe file", ["make"], "make deploy"),
    ("cargo runs build.rs", ["cargo"], "cargo build"),
    ("go generate", ["go"], "go generate ./..."),
    ("exec wrapper", ["xargs"], "xargs rm"),
    ("env wrapper", ["env"], "env FOO=1 rm -rf /"),
    ("sudo", ["sudo"], "sudo rm -rf /"),
    ("npx runs an arbitrary package", ["npx"], "npx some-package"),
    ("uvx", ["uvx"], "uvx some-tool"),
    ("inline code", ["python"], '''python -c "import os; os.system('rm -rf /')"'''),
    ("find -exec", ["find"], "find . -exec rm {} +"),
    ("find -delete", ["find"], "find . -delete"),
    ("command substitution", ["echo"], "echo `cat /etc/shadow`"),
    ("redirection", ["echo"], "echo x > /etc/cron.d/evil"),
    ("docker", ["docker"], "docker run --rm -v /:/host alpine sh"),
    ("ssh", ["ssh"], "ssh host rm -rf /"),
]


@pytest.mark.parametrize(
    "label,allowlist,command", DANGEROUS_BARE, ids=[r[0] for r in DANGEROUS_BARE]
)
def test_dangerous_commands_never_auto_run(workspace, label, allowlist, command):
    eng = _engine(workspace, allowed_commands=allowlist)
    assert eng.evaluate("run_shell", {"command": command}).allowed is False, label


SPECIFIC_RULES_STILL_WORK = [
    ("npm test", ["npm test"], "npm test"),
    ("npm test with extra flags", ["npm test"], "npm test -- --watch"),
    ("make build", ["make build"], "make build"),
    ("a named script", ["python scripts/report.py"], "python scripts/report.py --json"),
    ("cargo test", ["cargo test"], "cargo test"),
]


@pytest.mark.parametrize(
    "label,allowlist,command",
    SPECIFIC_RULES_STILL_WORK,
    ids=[r[0] for r in SPECIFIC_RULES_STILL_WORK],
)
def test_a_rule_that_names_a_subcommand_still_auto_runs(workspace, label, allowlist, command):
    """The control is against a BARE entry. A rule naming a subcommand is the operator
    deciding about a specific thing, and must stay usable — a gate people route around is
    not a gate."""
    eng = _engine(workspace, allowed_commands=allowlist)
    assert eng.evaluate("run_shell", {"command": command}).allowed is True, label


# -- 4. Browser upload / screenshot are root-scoped (OW-SEC-012) -----------------


def _browser_tools(roots):
    from coworker.connectors.browser_automation import make_browser_automation_tools

    return {t.__name__: t for t in make_browser_automation_tools(roots=roots)}


def test_browser_upload_cannot_read_outside_the_roots(workspace):
    ws, outside, _second = workspace
    tools = _browser_tools([RootDir(path=ws, writable=True)])
    out = tools["browser_upload_file"]("#file", str(outside / "secrets.txt"))
    assert "outside the session's directories" in out.get("error", "")


def test_browser_upload_rejects_traversal(workspace):
    ws, outside, _second = workspace
    tools = _browser_tools([RootDir(path=ws, writable=True)])
    out = tools["browser_upload_file"]("#file", str(ws / ".." / "outside" / "secrets.txt"))
    assert "outside the session's directories" in out.get("error", "")


def test_browser_screenshot_cannot_write_outside_a_writable_root(workspace):
    ws, outside, _second = workspace
    tools = _browser_tools([RootDir(path=ws, writable=True)])
    out = tools["browser_screenshot"](str(outside / "shot.png"))
    assert "outside the session's writable directories" in out.get("error", "")


def test_browser_screenshot_refuses_a_read_only_root(workspace):
    ws, _outside, second = workspace
    tools = _browser_tools([RootDir(path=ws, writable=True), RootDir(path=second, writable=False)])
    out = tools["browser_screenshot"](str(second / "shot.png"))
    assert "writable" in out.get("error", "")


def test_browser_tools_with_no_roots_refuse_rather_than_defaulting_open():
    tools = _browser_tools([])
    assert "error" in tools["browser_upload_file"]("#file", "/etc/passwd")
    assert "error" in tools["browser_screenshot"]("/tmp/x.png")


# -- 5. Canonical file writes stay scoped (OW-SEC-011) --------------------------

WRITE_ESCAPES = [
    ("absolute outside", "/etc/cron.d/evil"),
    ("traversal", "../outside/secrets.txt"),
    ("home", "~/.bashrc"),
]


@pytest.mark.parametrize("label,path", WRITE_ESCAPES, ids=[r[0] for r in WRITE_ESCAPES])
def test_writes_cannot_escape_a_writable_root(workspace, label, path):
    eng = _engine(workspace)
    assert eng.evaluate("write_file", {"path": path, "content": "x"}).allowed is False, label


def test_write_into_a_read_only_second_root_is_refused(workspace):
    _ws, _outside, second = workspace
    eng = _engine(workspace, extra_roots=[RootDir(path=second, writable=False)])
    d = eng.evaluate("write_file", {"path": str(second / "new.txt"), "content": "x"})
    assert d.allowed is False


def test_in_root_write_is_scoped_ok(workspace):
    ws = workspace[0]
    eng = _engine(workspace, mode=Mode.BYPASS_APPROVALS)
    assert eng.evaluate("write_file", {"path": str(ws / "out.txt"), "content": "x"}).allowed is True


# -- 6. Session id traversal (OW-SEC-014) ---------------------------------------

UNSAFE_IDS = [
    "../../evil",
    "..",
    ".",
    "a/b",
    "a\\b",
    "a b",
    "",
    "x" * 129,
    "sess;rm -rf /",
    "sess\x00",
    "%2e%2e%2fevil",
]


@pytest.mark.parametrize("sid", UNSAFE_IDS)
def test_unsafe_session_ids_are_rejected(sid):
    assert is_safe_session_id(sid) is False


@pytest.mark.parametrize("sid", ["abc", "A-1_b", "x" * 128])
def test_safe_session_ids_are_accepted(sid):
    assert is_safe_session_id(sid) is True


@pytest.mark.parametrize("sid", ["../../evil", "a/b", ".."])
def test_conversation_file_path_rejects_a_crafted_id(tmp_path, sid):
    """`_file` is the single chokepoint for every conversation-file path: it rejects ids
    that are not a safe path component AND re-confirms the resolved parent."""
    from coworker.conversations import ConversationStore

    store = ConversationStore(tmp_path)
    with pytest.raises(ValueError):
        store._file(sid)


def test_conversation_file_path_accepts_a_normal_id(tmp_path):
    from coworker.conversations import ConversationStore

    store = ConversationStore(tmp_path)
    assert store._file("abc123").name == "abc123.jsonl"
