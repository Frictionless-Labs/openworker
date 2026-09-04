"""Address guard for URLs the model chooses.

`web_fetch` and `browser_open_url` take a URL straight from the model, and the model's
input is untrusted by design — it reads web pages, email and Slack messages, all of which
are documented as "data, not instructions". A page that talks the agent into fetching
`http://169.254.169.254/` or `http://127.0.0.1:11434/` turns a read-only research tool into
a probe of the machine's own network position, and `web_fetch` is `requires_approval=False`,
so no prompt ever appears.

This blocks the ranges that are only reachable *because* OpenWorker runs on the user's
machine: loopback, RFC1918 and other private space, link-local (which covers the cloud
metadata endpoint at 169.254.169.254), and the reserved/multicast blocks.

Every hop is checked, not just the first: `follow_redirects=True` otherwise lets a public
URL 302 straight to loopback, which is the standard way this filter is bypassed.

DNS rebinding is closed by connection-level pinning: `get_checked` rewrites each hop so the
client connects to the exact address that passed the check (name in Host and SNI, so virtual
hosting and certificate verification still see the name). A record with a ~0 TTL that flips
to 127.0.0.1 between the check and the connect therefore changes nothing — the client never
resolves the name itself. `check_url` alone (browser_open_url's pre-check) still carries the
resolve-twice gap, because the browser owns its own connections and cannot be pinned from here.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_REDIRECTS = 5

# RFC 6598 shared address space. Python's is_private misses it, but it is carrier grade
# NAT space and Tailscale hands out internal hosts here (100.64.0.0/10), so a fetch to it
# is the same "reach the machine's network position" class as RFC1918.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _blocked_reason(ip: ipaddress._BaseAddress) -> Optional[str]:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (includes the cloud metadata endpoint)"
    if ip.is_private:
        return "a private network"
    if ip.version == 4 and ip in _CGNAT:
        return "shared address space (CGNAT / RFC 6598)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "a reserved range"
    return None


def _vet(url: str) -> tuple[Optional[str], Optional[str]]:
    """(refusal reason, address to pin the connection to).

    The reason is None when the URL may be fetched. The address is None for literal-IP
    URLs (the URL already names the connection target) and the first resolved answer
    otherwise — valid to pin because a refusal is returned when *any* answer lands in a
    blocked range, so a name with both a public and a private A record cannot slip through.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "url must start with http:// or https://", None
    host = parts.hostname
    if not host:
        return "url has no host", None

    # A literal address needs no lookup.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        reason = _blocked_reason(literal)
        return (f"refusing to fetch {host}: {reason}" if reason else None), None

    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except OSError as exc:
        return f"could not resolve {host}: {exc}", None

    pin: Optional[str] = None
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        # ::ffff:127.0.0.1 and friends must be judged as the v4 address they carry.
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        reason = _blocked_reason(ip)
        if reason:
            return f"refusing to fetch {host} ({ip}): {reason}", None
        if pin is None:
            pin = raw
    return None, pin


def check_url(url: str) -> Optional[str]:
    """None if the URL may be fetched, else a human-readable refusal reason.

    Resolves the host and rejects when *any* answer lands in a blocked range, so a name
    with both a public and a private A record cannot be used to slip through.
    """
    return _vet(url)[0]


def _pinned(url: str, ip: str) -> tuple[str, dict, dict]:
    """Rewrite `url` so the client connects to `ip` while presenting the original name.

    Returns (request_url, headers, extensions): the URL carries the vetted address so the
    client never resolves the name itself, Host carries the name (and any explicit port)
    for virtual hosting, and `sni_hostname` keeps the TLS handshake — including certificate
    verification — against the name rather than the address.
    """
    parts = urlsplit(url)
    host = parts.hostname
    addr = f"[{ip}]" if ":" in ip else ip
    userinfo, _, _ = parts.netloc.rpartition("@")
    netloc = (f"{userinfo}@" if userinfo else "") + addr
    host_header = host
    if parts.port is not None:
        netloc += f":{parts.port}"
        host_header += f":{parts.port}"
    request_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
    return request_url, {"Host": host_header}, extensions


def get_checked(client, url: str, *, max_redirects: int = MAX_REDIRECTS):
    """GET `url`, validating and pinning the address before every hop.

    `client` must be built with `follow_redirects=False`; redirects are walked here so each
    Location is checked. Every hop connects to the exact address that passed its check (see
    `_pinned`), so a rebinding name cannot swap targets between check and connect. Returns
    the final response, with the final *logical* URL — the name, not the pinned address —
    stashed as `resp.extensions["logical_url"]` for callers that display it. Raises
    `PermissionError` when a hop is refused, `RuntimeError` when the budget is exhausted.
    """
    seen = url
    for _ in range(max_redirects + 1):
        reason, pin = _vet(seen)
        if reason:
            raise PermissionError(reason)
        if pin is None:
            resp = client.get(seen)
        else:
            request_url, headers, extensions = _pinned(seen, pin)
            resp = client.get(request_url, headers=headers, extensions=extensions)
        if resp.status_code not in (301, 302, 303, 307, 308):
            ext = getattr(resp, "extensions", None)
            if isinstance(ext, dict):
                ext["logical_url"] = seen
            return resp
        location = resp.headers.get("location")
        if not location:
            return resp
        # Resolved against the logical URL, not resp.url — the latter names the pinned
        # address, and a relative Location must stay on the original host.
        seen = urljoin(seen, location)
    raise RuntimeError(f"too many redirects (>{max_redirects})")


# -- OAuth / MCP endpoint policy (OWH M05 / OW-SEC-009) --------------------------
#
# Same address policy as `check_url`, one notch stricter on scheme. An MCP server's
# authorization-server metadata is a STRANGER'S CLAIM about where to send a client
# registration and a token exchange — the confused-deputy shape MCP's own security guidance
# names. Plain HTTP there would put a bearer token on the wire in cleartext and make the
# endpoint trivially spoofable on a shared network, so `http://` is refused even for hosts
# the address policy would otherwise allow.
#
# Loopback is refused along with the rest of private space. That is a deliberate narrowing:
# a locally-run MCP server reachable over stdio needs no OAuth at all, and the alternative —
# permitting `http://127.0.0.1:…` here — is exactly the bypass hostile metadata would use
# to point a token exchange at another service on the operator's own machine.

_SAFE_ENDPOINT_SCHEMES = ("https",)


def check_endpoint(
    url: str, *, purpose: str = "endpoint", scheme_only: bool = False
) -> Optional[str]:
    """None if this OAuth/MCP endpoint may be contacted, else a refusal reason.

    `purpose` names the hop in the refusal ("token endpoint", "registration endpoint", …)
    so a rejection says which claim was refused rather than only which address.

    `scheme_only=True` checks the scheme and skips address resolution. It is for
    CONSTRUCTION-time checks — validating a configured server URL before any request
    exists. Resolution is deliberately not done there: a DNS blip would otherwise turn a
    retryable network error into a hard construction failure, and it would buy nothing,
    because the address policy is applied again at the point of use, on the request that
    actually leaves (see `mcp/oauth.py::async_auth_flow`). Point-of-use recheck is the rule
    that matters here; a construction-time resolve is a second, weaker copy of it.
    """
    raw = (url or "").strip()
    if not raw:
        return f"refusing an empty {purpose} URL"
    scheme = urlsplit(raw).scheme.lower()
    if scheme not in _SAFE_ENDPOINT_SCHEMES:
        return (
            f"refusing {purpose} {raw}: MCP OAuth endpoints must use https "
            f"(got {scheme or 'no scheme'})"
        )
    if scheme_only:
        # A literal address needs no lookup, so the address policy still applies here —
        # `scheme_only` skips RESOLUTION, not judgement. Only a name is deferred to the
        # point of use.
        host = urlsplit(raw).hostname or ""
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            return None
        blocked = _blocked_reason(literal)
        return f"refusing {purpose} {raw}: {blocked}" if blocked else None
    reason = check_url(raw)
    if reason:
        return f"refusing {purpose} {raw}: {reason}"
    return None


def check_endpoints(pairs: "Iterable[tuple[str, str]]") -> Optional[str]:
    """First refusal across `(purpose, url)` pairs, skipping empty URLs. Fail-closed: a
    single bad endpoint refuses the whole metadata document, because a client that
    registered against a hostile registration endpoint is already compromised even if its
    token endpoint was fine."""
    for purpose, url in pairs:
        if not url:
            continue
        reason = check_endpoint(str(url), purpose=purpose)
        if reason:
            return reason
    return None
