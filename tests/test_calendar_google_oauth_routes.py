"""Behavioral route regressions for the Google CalDAV account contract."""

import asyncio

import pytest
from fastapi import HTTPException

import routes.calendar_routes as calendar_routes
import routes.prefs_routes as prefs_routes
import src.secret_storage as secret_storage
from src import google_oauth


class _Request:
    def __init__(self, body=None):
        self.body = body or {}

    async def json(self):
        return self.body


def _endpoint(router, suffix, method):
    for route in router.routes:
        if route.path.endswith(suffix) and method in route.methods:
            return route.endpoint
    raise AssertionError(f"Missing {method} {suffix} route")


@pytest.fixture
def route_context(monkeypatch):
    state = {
        "prefs": {
            "caldav_accounts": [
                {
                    "id": "google-1",
                    "label": "Google",
                    "url": "https://apidata.googleusercontent.com/caldav/v2/me@example.com/user",
                    "auth_type": "oauth2_google",
                    "oauth_scope": google_oauth.CALDAV_SCOPE,
                    "oauth_client_id": "client-public",
                    "oauth_client_secret": "enc:client-secret",
                    "oauth_access_token": "enc:access-secret",
                    "oauth_refresh_token": "enc:refresh-secret",
                    "oauth_expires_at": 9999999999,
                }
            ]
        }
    }

    monkeypatch.setattr(prefs_routes, "_load_for_user", lambda owner: state["prefs"])
    monkeypatch.setattr(
        prefs_routes, "_save_for_user", lambda owner, value: state.update(prefs=value)
    )

    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    monkeypatch.setattr(
        secret_storage,
        "decrypt",
        lambda value: value[4:] if str(value).startswith("enc:") else (value or ""),
    )
    monkeypatch.setattr(calendar_routes, "_require_user", lambda request: "alice")
    return state, calendar_routes.setup_calendar_routes()


def test_callback_error_is_generic_and_does_not_reflect_markup(route_context):
    _state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    attacker_text = '<img src=x onerror="alert(1)">'
    response = asyncio.run(callback(_Request(), error=attacker_text))
    body = response.body.decode("utf-8")
    assert response.status_code == 400
    assert attacker_text not in body
    assert "onerror" not in body


def test_callback_decrypt_failure_returns_invalid_config(route_context, monkeypatch):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    def broken_decrypt(_value):
        raise RuntimeError("corrupt ciphertext")

    monkeypatch.setattr(secret_storage, "decrypt", broken_decrypt)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 400
    assert "configuration is invalid" in response.body.decode("utf-8")
    assert state["prefs"]["caldav_accounts"][0]["oauth_access_token"] == "enc:access-secret"


def test_callback_empty_decrypted_secret_returns_invalid_config(route_context, monkeypatch):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    monkeypatch.setattr(secret_storage, "decrypt", lambda _value: "")
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 400
    assert "configuration is invalid" in response.body.decode("utf-8")
    assert state["prefs"]["caldav_accounts"][0]["oauth_access_token"] == "enc:access-secret"


def test_callback_without_new_or_stored_refresh_token_is_actionable(
    route_context, monkeypatch
):
    state, router = route_context
    state["prefs"]["caldav_accounts"][0]["oauth_refresh_token"] = ""
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    async def exchange_without_refresh(*args):
        return {"access_token": "new-access", "expires_at": 1234}

    monkeypatch.setattr(google_oauth, "exchange_code", exchange_without_refresh)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 400
    assert "refresh token" in response.body.decode("utf-8").lower()
    assert state["prefs"]["caldav_accounts"][0]["oauth_access_token"] == "enc:access-secret"


def test_callback_rejects_corrupt_stored_refresh_token_when_google_omits_one(
    route_context, monkeypatch
):
    state, router = route_context
    state["prefs"]["caldav_accounts"][0]["oauth_refresh_token"] = "enc:corrupt"
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")
    real_decrypt = secret_storage.decrypt

    def decrypt_with_corrupt_refresh(value):
        if value == "enc:corrupt":
            raise ValueError("corrupt refresh token")
        return real_decrypt(value)

    async def exchange_without_refresh(*args):
        return {"access_token": "new-access", "expires_at": 1234}

    monkeypatch.setattr(secret_storage, "decrypt", decrypt_with_corrupt_refresh)
    monkeypatch.setattr(google_oauth, "exchange_code", exchange_without_refresh)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 400
    assert "refresh token" in response.body.decode("utf-8").lower()
    assert state["prefs"]["caldav_accounts"][0]["oauth_access_token"] == "enc:access-secret"


def test_callback_records_current_read_write_scope(route_context, monkeypatch):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    async def successful_exchange(*args):
        return {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "expires_at": 1234,
            "scope": google_oauth.CALDAV_SCOPE,
        }

    monkeypatch.setattr(google_oauth, "exchange_code", successful_exchange)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 200
    account = state["prefs"]["caldav_accounts"][0]
    assert account["oauth_scope"] == google_oauth.CALDAV_SCOPE
    assert account["oauth_access_token"] == "enc:new-access"
    assert account["oauth_refresh_token"] == "enc:new-refresh"


def test_callback_rejects_and_records_insufficient_granted_scope(
    route_context, monkeypatch
):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    async def readonly_exchange(*args):
        return {
            "access_token": "readonly-access",
            "refresh_token": "readonly-refresh",
            "expires_at": 1234,
            "scope": "https://www.googleapis.com/auth/calendar.readonly",
        }

    revoked = []

    async def record_revoke(token):
        revoked.append(token)

    monkeypatch.setattr(google_oauth, "exchange_code", readonly_exchange)
    monkeypatch.setattr(google_oauth, "revoke_token", record_revoke)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 403
    assert revoked == ["readonly-refresh"]
    account = state["prefs"]["caldav_accounts"][0]
    assert account["oauth_scope"].endswith("/calendar.readonly")
    assert account["oauth_access_token"] == ""
    assert account["oauth_refresh_token"] == ""
    assert account["oauth_expires_at"] == 0


def test_callback_does_not_write_tokens_after_concurrent_auth_switch(
    route_context, monkeypatch
):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    async def exchange_and_switch(*args):
        state["prefs"]["caldav_accounts"][0]["auth_type"] = "basic"
        return {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "expires_at": 1234,
        }

    monkeypatch.setattr(google_oauth, "exchange_code", exchange_and_switch)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 409
    account = state["prefs"]["caldav_accounts"][0]
    assert account["auth_type"] == "basic"
    assert account["oauth_access_token"] == "enc:access-secret"


def test_callback_binds_state_to_current_user(route_context):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("bob", "google-1")

    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 400
    assert state["prefs"]["caldav_accounts"][0]["oauth_access_token"] == "enc:access-secret"


def test_callback_empty_code_consumes_valid_state_without_exchange(route_context):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    response = asyncio.run(callback(_Request(), state=oauth_state, code=""))

    assert response.status_code == 400
    assert "incomplete" in response.body.decode("utf-8").lower()
    assert google_oauth.consume_state(oauth_state) is None
    assert state["prefs"]["caldav_accounts"][0]["oauth_access_token"] == "enc:access-secret"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("oauth_client_id", "changed-client"), ("oauth_client_secret", "enc:changed-secret")],
)
def test_callback_does_not_write_after_concurrent_credential_change(
    route_context, monkeypatch, field, replacement
):
    state, router = route_context
    callback = _endpoint(router, "/oauth/google/callback", "GET")
    oauth_state = google_oauth.generate_state("alice", "google-1")

    async def exchange_and_change(*args):
        state["prefs"]["caldav_accounts"][0][field] = replacement
        return {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "expires_at": 1234,
        }

    monkeypatch.setattr(google_oauth, "exchange_code", exchange_and_change)
    response = asyncio.run(callback(_Request(), code="code", state=oauth_state))

    assert response.status_code == 409
    account = state["prefs"]["caldav_accounts"][0]
    assert account["oauth_access_token"] == "enc:access-secret"


def test_google_account_list_exposes_client_id_but_no_secret_or_tokens(route_context):
    _state, router = route_context
    list_accounts = _endpoint(router, "/config/accounts", "GET")
    result = asyncio.run(list_accounts(_Request()))
    account = result["accounts"][0]
    assert account["oauth_client_id"] == "client-public"
    assert "oauth_client_secret" not in account
    assert "oauth_access_token" not in account
    assert "oauth_refresh_token" not in account


def test_google_account_list_accepts_existing_full_calendar_grant(route_context):
    state, router = route_context
    state["prefs"]["caldav_accounts"][0][
        "oauth_scope"
    ] = google_oauth.CALENDAR_FULL_SCOPE
    list_accounts = _endpoint(router, "/config/accounts", "GET")

    result = asyncio.run(list_accounts(_Request()))

    account = result["accounts"][0]
    assert account["has_access_token"] is True
    assert account["is_connected"] is True


def test_google_account_list_marks_legacy_pull_grant_for_reconnect(route_context):
    state, router = route_context
    state["prefs"]["caldav_accounts"][0].pop("oauth_scope")
    list_accounts = _endpoint(router, "/config/accounts", "GET")

    result = asyncio.run(list_accounts(_Request()))

    account = result["accounts"][0]
    assert account["has_access_token"] is True
    assert account["is_connected"] is True
    assert account["needs_reconnect"] is True


def test_google_account_list_tolerates_malformed_encrypted_values(route_context, monkeypatch):
    state, router = route_context
    state["prefs"]["caldav_accounts"].append(
        {
            "id": "basic-bad",
            "label": "Broken basic",
            "url": "https://calendar.example.test/dav",
            "auth_type": "basic",
            "username": "user",
            "password": 123,
        }
    )

    def broken_decrypt(_value):
        raise ValueError("not a Fernet token")

    monkeypatch.setattr(secret_storage, "decrypt", broken_decrypt)
    list_accounts = _endpoint(router, "/config/accounts", "GET")
    result = asyncio.run(list_accounts(_Request()))

    by_id = {account["id"]: account for account in result["accounts"]}
    assert by_id["google-1"]["has_access_token"] is False
    assert by_id["google-1"]["is_connected"] is False
    assert by_id["basic-bad"]["has_password"] is False


def test_google_account_list_uses_plaintext_fallback_only_for_basic_password(
    route_context, monkeypatch
):
    state, router = route_context
    state["prefs"]["caldav_accounts"].append(
        {
            "id": "basic-legacy",
            "label": "Legacy basic",
            "url": "https://calendar.example.test/dav",
            "auth_type": "basic",
            "username": "user",
            "password": "legacy-password",
        }
    )

    def broken_decrypt(_value):
        raise ValueError("not encrypted")

    monkeypatch.setattr(secret_storage, "decrypt", broken_decrypt)
    list_accounts = _endpoint(router, "/config/accounts", "GET")
    result = asyncio.run(list_accounts(_Request()))

    by_id = {account["id"]: account for account in result["accounts"]}
    assert by_id["basic-legacy"]["has_password"] is True
    assert by_id["google-1"]["has_access_token"] is False
    assert by_id["google-1"]["is_connected"] is False


def test_add_account_returns_new_id(route_context):
    state, router = route_context
    add = _endpoint(router, "/config/accounts", "POST")
    result = asyncio.run(
        add(
            _Request(
                {
                    "auth_type": "oauth2_google",
                    "url": "https://apidata.googleusercontent.com/caldav/v2/new@example.com/user",
                    "oauth_client_id": "client-id",
                    "oauth_client_secret": "client-secret",
                }
            )
        )
    )

    assert result["ok"] is True
    assert result["id"]
    assert any(account["id"] == result["id"] for account in state["prefs"]["caldav_accounts"])


@pytest.mark.parametrize(
    "body",
    [
        {"auth_type": "basic", "url": 123, "username": "user", "password": "pw"},
        {"auth_type": "basic", "url": "https://8.8.8.8/dav", "label": 123, "username": "user", "password": "pw"},
    ],
)
def test_add_rejects_non_string_url_and_label(route_context, body):
    _state, router = route_context
    add = _endpoint(router, "/config/accounts", "POST")

    with pytest.raises(HTTPException) as error:
        asyncio.run(add(_Request(body)))
    assert error.value.status_code == 400


@pytest.mark.parametrize(
    "body",
    [
        {"auth_type": "oauth2_google", "url": 123},
        {"auth_type": "oauth2_google", "url": None},
        {"auth_type": "oauth2_google", "label": {"bad": True}},
        {"auth_type": "oauth2_google", "label": None},
    ],
)
def test_update_rejects_non_string_url_and_label(route_context, body):
    _state, router = route_context
    update = _endpoint(router, "/config/accounts/{account_id}", "PUT")

    with pytest.raises(HTTPException) as error:
        asyncio.run(update("google-1", _Request(body)))
    assert error.value.status_code == 400


def test_test_connection_handles_corrupt_google_ciphertext(route_context, monkeypatch):
    _state, router = route_context
    test_connection = _endpoint(router, "/test", "POST")

    def broken_decrypt(_value):
        raise RuntimeError("corrupt ciphertext")

    monkeypatch.setattr(secret_storage, "decrypt", broken_decrypt)
    result = asyncio.run(test_connection(_Request({"account_id": "google-1"})))

    assert result["ok"] is False
    assert "invalid" in result["error"].lower()


@pytest.mark.parametrize(
    ("body", "expected_client_id"),
    [
        (
            {
                "auth_type": "oauth2_google",
                "url": "https://apidata.googleusercontent.com/caldav/v2/me@example.com/user",
                "oauth_client_id": "changed-client",
                "oauth_client_secret": "",
            },
            "changed-client",
        ),
        (
            {
                "auth_type": "oauth2_google",
                "url": "https://apidata.googleusercontent.com/caldav/v2/me@example.com/user",
                "oauth_client_id": "",
                "oauth_client_secret": "changed-secret",
            },
            "client-public",
        ),
    ],
)
def test_google_credential_change_invalidates_existing_tokens(
    route_context, body, expected_client_id
):
    state, router = route_context
    update = _endpoint(router, "/config/accounts/{account_id}", "PUT")

    result = asyncio.run(update("google-1", _Request(body)))

    assert result == {"ok": True}
    account = state["prefs"]["caldav_accounts"][0]
    assert account["oauth_client_id"] == expected_client_id
    assert account["oauth_access_token"] == ""
    assert account["oauth_refresh_token"] == ""
    assert account["oauth_expires_at"] == 0


def test_google_url_change_invalidates_existing_tokens(route_context):
    state, router = route_context
    update = _endpoint(router, "/config/accounts/{account_id}", "PUT")

    result = asyncio.run(
        update(
            "google-1",
            _Request(
                {
                    "auth_type": "oauth2_google",
                    "url": "https://apidata.googleusercontent.com/caldav/v2/other@example.com/user",
                }
            ),
        )
    )

    assert result == {"ok": True}
    account = state["prefs"]["caldav_accounts"][0]
    assert account["oauth_access_token"] == ""
    assert account["oauth_refresh_token"] == ""
    assert account["oauth_expires_at"] == 0


def test_update_validates_retained_basic_url_for_selected_auth_type(route_context):
    state, router = route_context
    state["prefs"]["caldav_accounts"].append(
        {
            "id": "basic-invalid",
            "label": "Invalid",
            "url": "https://localhost/private",
            "auth_type": "basic",
            "username": "user",
            "password": "enc:password",
        }
    )
    update = _endpoint(router, "/config/accounts/{account_id}", "PUT")

    with pytest.raises(HTTPException) as error:
        asyncio.run(update("basic-invalid", _Request({"auth_type": "basic"})))
    assert error.value.status_code == 400


def test_empty_client_id_edit_preserves_existing_value(route_context):
    state, router = route_context
    update = _endpoint(router, "/config/accounts/{account_id}", "PUT")
    result = asyncio.run(
        update(
            "google-1",
            _Request(
                {
                    "auth_type": "oauth2_google",
                    "url": "https://apidata.googleusercontent.com/caldav/v2/me@example.com/user",
                    "oauth_client_id": "",
                    "oauth_client_secret": "",
                }
            ),
        )
    )
    assert result == {"ok": True}
    assert state["prefs"]["caldav_accounts"][0]["oauth_client_id"] == "client-public"


def test_invalid_auth_type_and_arbitrary_google_url_are_rejected(route_context):
    _state, router = route_context
    add = _endpoint(router, "/config/accounts", "POST")
    with pytest.raises(HTTPException) as invalid_type:
        asyncio.run(add(_Request({"auth_type": "arbitrary", "url": "https://example.test"})))
    assert invalid_type.value.status_code == 400

    with pytest.raises(HTTPException) as invalid_url:
        asyncio.run(
            add(
                _Request(
                    {
                        "auth_type": "oauth2_google",
                        "url": "https://evil.example.test/caldav/v2/me@example.com/user",
                        "oauth_client_id": "client",
                        "oauth_client_secret": "secret",
                    }
                )
            )
        )
    assert invalid_url.value.status_code == 400


def test_switching_from_basic_drops_old_basic_credentials(route_context):
    state, router = route_context
    state["prefs"]["caldav_accounts"].append(
        {
            "id": "basic-1",
            "label": "Basic",
            "url": "https://calendar.example.test/dav",
            "auth_type": "basic",
            "username": "old-user",
            "password": "enc:old-password",
        }
    )
    update = _endpoint(router, "/config/accounts/{account_id}", "PUT")
    asyncio.run(
        update(
            "basic-1",
            _Request(
                {
                    "auth_type": "oauth2_google",
                    "url": "https://apidata.googleusercontent.com/caldav/v2/me@example.com/user",
                    "oauth_client_id": "new-client",
                    "oauth_client_secret": "new-secret",
                }
            ),
        )
    )
    account = next(item for item in state["prefs"]["caldav_accounts"] if item["id"] == "basic-1")
    assert account["auth_type"] == "oauth2_google"
    assert "username" not in account and "password" not in account
    assert account["oauth_client_id"] == "new-client"
