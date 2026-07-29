"""Google OAuth 2.0 helpers for CalDAV authentication.

Handles the authorization code flow: building the consent URL, exchanging the
code for tokens, and refreshing access tokens when they expire.
"""

import os
import secrets
import time
from urllib.parse import urlencode

import httpx

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
# This integration only pulls calendar data; request the least-privileged
# read-only scope for new consent grants.
CALDAV_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"


class GoogleOAuthCredentialError(RuntimeError):
    """The refresh credentials were rejected and a new grant is required."""

    def __init__(self, error_code: str):
        self.error_code = error_code
        super().__init__(f"Google OAuth token request failed: {error_code}")

# Google Cloud must be configured with this exact callback for the desktop
# application.  Deployments behind a fixed reverse proxy may opt into one
# explicit override, but both sides of the flow always resolve it through
# ``get_redirect_uri``.
GOOGLE_REDIRECT_URI = "http://127.0.0.1:7860/api/calendar/oauth/google/callback"
GOOGLE_REDIRECT_URI_ENV = "ODYSSEUS_GOOGLE_OAUTH_REDIRECT_URI"


def get_redirect_uri() -> str:
    """Return the canonical OAuth callback URI for this installation."""
    override = os.environ.get(GOOGLE_REDIRECT_URI_ENV, "").strip()
    return override or GOOGLE_REDIRECT_URI

# State is intentionally process-local: the desktop launcher runs one
# application worker, and persisting OAuth state would expand the data model
# and deployment surface without improving this supported use case.
_STATE_TTL = 600  # 10 minutes
_STATE_MAX_PENDING = 256
_pending: dict[str, dict] = {}


def generate_state(owner: str, account_id: str) -> str:
    _evict_expired()
    while len(_pending) >= _STATE_MAX_PENDING:
        oldest = min(_pending, key=lambda key: _pending[key]["ts"])
        del _pending[oldest]
    state = secrets.token_urlsafe(32)
    _pending[state] = {"owner": owner, "account_id": account_id, "ts": time.time()}
    return state


def consume_state(
    state: str, owner: str | None = None, account_id: str | None = None
) -> dict | None:
    """Consume a pending state once, optionally enforcing its owner binding."""
    _evict_expired()
    entry = _pending.pop(state, None)
    if (
        entry
        and time.time() - entry["ts"] < _STATE_TTL
        and (owner is None or entry.get("owner") == owner)
        and (account_id is None or entry.get("account_id") == account_id)
    ):
        return entry
    return None


def _evict_expired() -> None:
    now = time.time()
    stale = [k for k, v in _pending.items() if now - v["ts"] >= _STATE_TTL]
    for k in stale:
        del _pending[k]


def build_auth_url(client_id: str, redirect_uri: str, state: str) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": CALDAV_SCOPE,
        "access_type": "offline",
        "prompt": "consent",  # always request refresh token
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code(
    client_id: str, client_secret: str, code: str, redirect_uri: str
) -> dict:
    """Exchange an authorization code for access + refresh tokens.
    Returns {access_token, refresh_token, expires_at}."""
    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as cx:
        r = await cx.post(GOOGLE_TOKEN_URL, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        })
        r.raise_for_status()
        data = r.json()
    return {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", ""),
        "expires_at": int(time.time()) + data.get("expires_in", 3600) - 60,
    }


async def refresh_access_token(
    client_id: str, client_secret: str, refresh_token: str
) -> dict:
    """Use the refresh token to obtain a new access token.
    Returns {access_token, expires_at}, optionally including a rotated
    refresh_token returned by Google.
    """
    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as cx:
        r = await cx.post(GOOGLE_TOKEN_URL, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        })
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            try:
                error_code = r.json().get("error")
            except Exception:
                error_code = None
            if error_code in {"invalid_grant", "invalid_client"}:
                raise GoogleOAuthCredentialError(error_code) from exc
            raise
        data = r.json()
    result = {
        "access_token": data["access_token"],
        "expires_at": int(time.time()) + data.get("expires_in", 3600) - 60,
    }
    if data.get("refresh_token"):
        result["refresh_token"] = data["refresh_token"]
    return result
