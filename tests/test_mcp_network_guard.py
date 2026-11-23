"""M05 MCP + browser network corpus (OW-SEC-009/010).

The threat: an MCP server's authorization-server metadata is a **stranger's claim** about
where to send a dynamic client registration and a token exchange. Point those at
`169.254.169.254` and the agent probes the machine's cloud-metadata endpoint on the
attacker's behalf, carrying the operator's own network position — the confused-deputy shape
MCP's security guidance names explicitly.

The corpus is deliberately blunt about what is PREVENTED and what is only DETECTED; see the
browser section.
"""

from __future__ import annotations

import asyncio

import pytest

from coworker import capabilities
from coworker.connectors.browser_automation import redirect_refusal
from coworker.web.guard import check_endpoint, check_url


@pytest.fixture(autouse=True)
def _hermetic_dns(monkeypatch):
    """Resolve every NAME to a fixed public address.

    A mandatory security gate must never be flaky (S6 health signal: "0 flaky mandatory
    security tests across last 10 runs"), and a corpus that does real DNS is flaky by
    construction — it fails in an offline CI runner and, worse, would pass for the wrong
    reason if a name stopped resolving. Literal-IP rows do no lookup and are unaffected;
    `localhost` is left alone so the loopback row exercises the real resolver path.
    """
    import socket

    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if host in ("localhost",):
            return real(host, port, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port or 443))]

    monkeypatch.setattr("coworker.web.guard.socket.getaddrinfo", fake)

# (label, url) — every one must be refused for an OAuth/MCP endpoint.
BLOCKED_ENDPOINTS = [
    ("loopback v4", "https://127.0.0.1/token"),
    ("loopback name", "https://localhost/token"),
    ("loopback v6", "https://[::1]/token"),
    ("cloud metadata", "https://169.254.169.254/latest/meta-data/"),
    ("link-local v4", "https://169.254.10.10/token"),
    ("rfc1918 10/8", "https://10.1.2.3/token"),
    ("rfc1918 172.16/12", "https://172.20.0.1/token"),
    ("rfc1918 192.168/16", "https://192.168.1.1/token"),
    ("cgnat / tailscale space", "https://100.100.5.5/token"),
    ("reserved", "https://240.0.0.1/token"),
    ("multicast", "https://224.0.0.1/token"),
    ("unspecified", "https://0.0.0.0/token"),
    ("ipv4-mapped loopback", "https://[::ffff:127.0.0.1]/token"),
    ("plain http to a public host", "http://example.com/token"),
    ("file scheme", "file:///etc/passwd"),
    ("ftp scheme", "ftp://example.com/token"),
    ("gopher scheme", "gopher://example.com/token"),
    ("javascript scheme", "javascript:alert(1)"),
    ("data scheme", "data:text/html,<script>x</script>"),
    ("scheme-less", "example.com/token"),
    ("empty", ""),
]


@pytest.mark.parametrize("label,url", BLOCKED_ENDPOINTS, ids=[r[0] for r in BLOCKED_ENDPOINTS])
def test_blocked_oauth_endpoints(label, url):
    reason = check_endpoint(url, purpose="token endpoint")
    assert reason, f"{label}: must be refused"
    assert isinstance(reason, str) and reason


def test_legitimate_public_https_endpoint_is_allowed():
    """The gate must not break the flow it exists to protect."""
    assert check_endpoint("https://mcp.granola.ai/mcp") is None


def test_endpoint_policy_is_stricter_than_the_web_fetch_policy_on_scheme_only():
    """Plain HTTP is fine for `web_fetch` and never fine for a token exchange."""
    assert check_url("http://example.com/page") is None
    assert check_endpoint("http://example.com/page") is not None


# -- Hostile MCP metadata --------------------------------------------------------


class _Metadata:
    """An authorization-server metadata document, as a hostile server would return it."""

    def __init__(self, **kw):
        self.authorization_endpoint = kw.get("authorization_endpoint", "https://example.com/auth")
        self.token_endpoint = kw.get("token_endpoint", "https://example.com/token")
        self.registration_endpoint = kw.get("registration_endpoint", "")
        self.revocation_endpoint = kw.get("revocation_endpoint", "")
        self.introspection_endpoint = kw.get("introspection_endpoint", "")


HOSTILE_METADATA = [
    ("registration → cloud metadata", {"registration_endpoint": "https://169.254.169.254/register"}),
    ("token → loopback", {"token_endpoint": "https://127.0.0.1:11434/token"}),
    ("authorization → private LAN", {"authorization_endpoint": "https://192.168.1.1/auth"}),
    ("revocation → link-local", {"revocation_endpoint": "https://169.254.1.1/revoke"}),
    ("introspection → cgnat", {"introspection_endpoint": "https://100.90.1.1/introspect"}),
    ("token downgraded to http", {"token_endpoint": "http://example.com/token"}),
]


@pytest.mark.parametrize("label,kw", HOSTILE_METADATA, ids=[r[0] for r in HOSTILE_METADATA])
def test_hostile_metadata_is_refused_whole(label, kw):
    """One bad endpoint refuses the WHOLE document: a client that registered against a
    hostile registration endpoint is already compromised even if its token endpoint was
    fine."""
    from coworker.mcp.oauth import _MetadataSeededProvider

    provider = _MetadataSeededProvider.__new__(_MetadataSeededProvider)
    provider.context = type("Ctx", (), {"oauth_metadata": _Metadata(**kw)})()
    assert provider._vet_metadata(), label


def test_clean_metadata_passes():
    from coworker.mcp.oauth import _MetadataSeededProvider

    provider = _MetadataSeededProvider.__new__(_MetadataSeededProvider)
    provider.context = type("Ctx", (), {"oauth_metadata": _Metadata()})()
    assert provider._vet_metadata() is None


def test_missing_metadata_is_not_an_error():
    from coworker.mcp.oauth import _MetadataSeededProvider

    provider = _MetadataSeededProvider.__new__(_MetadataSeededProvider)
    provider.context = type("Ctx", (), {"oauth_metadata": None})()
    assert provider._vet_metadata() is None


# -- The flow chokepoint ---------------------------------------------------------


async def test_auth_flow_refuses_a_blocked_request_before_it_is_yielded(monkeypatch):
    """Every OAuth request the SDK makes — discovery, DCR, token, refresh — passes through
    `async_auth_flow`. A blocked destination must raise instead of being yielded to httpx."""
    import httpx
    from mcp.client.auth import OAuthClientProvider

    from coworker.mcp.oauth import _MetadataSeededProvider

    async def fake_flow(self, request):
        yield httpx.Request("POST", "https://169.254.169.254/register")

    monkeypatch.setattr(OAuthClientProvider, "async_auth_flow", fake_flow)

    provider = _MetadataSeededProvider.__new__(_MetadataSeededProvider)
    provider.context = type("Ctx", (), {"oauth_metadata": None})()

    gen = provider.async_auth_flow(httpx.Request("GET", "https://example.com/mcp"))
    with pytest.raises(PermissionError) as excinfo:
        await gen.__anext__()
    assert "169.254.169.254" in str(excinfo.value)


async def test_auth_flow_passes_a_clean_request_through(monkeypatch):
    import httpx
    from mcp.client.auth import OAuthClientProvider

    from coworker.mcp.oauth import _MetadataSeededProvider

    async def fake_flow(self, request):
        yield httpx.Request("POST", "https://example.com/token")

    monkeypatch.setattr(OAuthClientProvider, "async_auth_flow", fake_flow)
    provider = _MetadataSeededProvider.__new__(_MetadataSeededProvider)
    provider.context = type("Ctx", (), {"oauth_metadata": None})()

    gen = provider.async_auth_flow(httpx.Request("GET", "https://example.com/mcp"))
    out = await gen.__anext__()
    assert str(out.url) == "https://example.com/token"
    await gen.aclose()


# -- The doors around the flow ---------------------------------------------------


@pytest.mark.parametrize(
    "server_url", ["http://mcp.test/mcp", "https://127.0.0.1:8080/mcp", "https://10.0.0.9/mcp"]
)
def test_build_auth_refuses_a_blocked_server_url(server_url, tmp_path):
    from coworker.mcp.oauth import build_auth
    from coworker.secrets import SecretStore

    with pytest.raises(PermissionError):
        build_auth("evil", server_url, SecretStore(tmp_path / "s.json"))


async def test_authorization_url_handed_to_the_system_browser_is_vetted():
    """The system browser carries the operator's own cookies and network position."""
    from coworker.mcp import oauth

    with pytest.raises(PermissionError):
        await oauth._open_browser("https://169.254.169.254/authorize?x=1")


# -- Browser: DETECTION, stated as such ------------------------------------------


@pytest.mark.parametrize(
    "final",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:11434/api/tags",
        "http://192.168.1.1/admin",
        "http://10.0.0.1/",
    ],
)
def test_redirect_to_a_blocked_destination_is_refused(final):
    assert redirect_refusal("https://short.test/x", final)


def test_no_redirect_and_same_url_are_not_refusals():
    assert redirect_refusal("https://ok.test/a", "https://ok.test/a") is None
    assert redirect_refusal("https://ok.test/a", "") is None


def test_public_to_public_redirect_is_allowed():
    assert redirect_refusal("https://short.test/x", "https://example.com/real") is None


def test_browser_automation_stays_disabled_because_this_is_detection_not_prevention():
    """OW-SEC-010 is honest about its limit: `redirect_refusal` runs AFTER the request has
    left the machine. It stops the agent READING or interacting with the landed page; it
    does not stop the request, and later JS/meta-refresh navigation is unchecked. Closing
    that needs a proxy vetting every hop. Until then the capability is OFF, and the release
    evidence must not claim SSRF closure for this surface."""
    assert capabilities.enabled("browser_automation") is False
    assert "detection" in capabilities.prerequisite("browser_automation").lower() or (
        "prevention" in capabilities.prerequisite("browser_automation").lower()
    )
    assert "prevent" in redirect_refusal.__doc__.lower()
    assert "cannot be prevented here" in redirect_refusal.__doc__


# -- Capability defaults ---------------------------------------------------------


def test_remote_mcp_is_off_by_default():
    assert capabilities.enabled("remote_mcp") is False
    with pytest.raises(PermissionError) as excinfo:
        capabilities.require("remote_mcp")
    assert "OW-SEC-009" in str(excinfo.value)


def test_an_unknown_capability_fails_closed():
    assert capabilities.enabled("definitely_not_a_capability") is False
    with pytest.raises(PermissionError):
        capabilities.require("definitely_not_a_capability")


@pytest.mark.parametrize("name", ["remote_mcp", "browser_automation"])
def test_the_two_capabilities_this_module_gates_stay_off(name):
    """Scoped to M05's own gates. The whole table — including the rule that nothing is ON
    without a recorded authorization — is asserted in tests/test_capability_defaults.py;
    duplicating a blanket "everything is OFF" here only created a second place to edit the
    moment a capability was legitimately authorized."""
    assert capabilities.enabled(name) is False, f"{name} must ship OFF"
    assert capabilities.prerequisite(name), f"{name} must name its prerequisite gate"


async def test_http_mcp_transport_is_refused_while_remote_mcp_is_off():
    """The gate is checked at the TRANSPORT, so no config path reaches the network around it."""
    from coworker.mcp.client import MCPManager
    from coworker.mcp.config import MCPServerDef

    manager = MCPManager()
    server = MCPServerDef(name="evil", transport="http", url="https://evil.test/mcp")
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    await manager._serve(server, ready, interactive=False)
    assert ready.done()
    with pytest.raises(PermissionError):
        ready.result()
