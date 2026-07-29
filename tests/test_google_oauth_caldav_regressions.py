"""Deterministic Google OAuth and direct CalDAV REPORT regressions."""

import asyncio
import hashlib
import sys
import types
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import core.database as cdb
from core.database import CalendarCal, CalendarEvent
import src.secret_storage as secret_storage
from src import caldav_sync, google_oauth


@pytest.fixture(autouse=True)
def clear_oauth_state():
    google_oauth._pending.clear()
    yield
    google_oauth._pending.clear()


def test_redirect_uri_default_and_explicit_override(monkeypatch):
    monkeypatch.delenv(google_oauth.GOOGLE_REDIRECT_URI_ENV, raising=False)
    assert (
        google_oauth.get_redirect_uri()
        == "http://127.0.0.1:7860/api/calendar/oauth/google/callback"
    )

    override = "https://desktop.example.test/oauth/callback"
    monkeypatch.setenv(google_oauth.GOOGLE_REDIRECT_URI_ENV, override)
    assert google_oauth.get_redirect_uri() == override

    auth_url = google_oauth.build_auth_url("client", override, "state")
    assert parse_qs(urlparse(auth_url).query)["scope"] == [google_oauth.CALDAV_SCOPE]
    assert set(google_oauth.CALDAV_SCOPE.split()) == {
        google_oauth.CALENDAR_EVENTS_SCOPE,
        google_oauth.CALENDAR_LIST_SCOPE,
    }


def test_oauth_state_is_bound_single_use_and_expires_without_sleep(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(google_oauth.time, "time", lambda: now[0])

    state = google_oauth.generate_state("alice", "account-a")
    assert google_oauth.consume_state(state, owner="bob", account_id="account-a") is None
    # A binding failure consumes the state and cannot be replayed.
    assert google_oauth.consume_state(state) is None

    state = google_oauth.generate_state("alice", "account-a")
    pending = google_oauth.consume_state(state, owner="alice", account_id="account-a")
    assert pending == {"owner": "alice", "account_id": "account-a", "ts": 100.0}
    assert google_oauth.consume_state(state) is None

    state = google_oauth.generate_state("alice", "account-a")
    now[0] += google_oauth._STATE_TTL
    assert google_oauth.consume_state(state) is None


def test_oauth_state_map_is_bounded(monkeypatch):
    monkeypatch.setattr(google_oauth, "_STATE_MAX_PENDING", 3)
    states = [
        google_oauth.generate_state("alice", f"account-{index}")
        for index in range(4)
    ]

    assert len(google_oauth._pending) == 3
    assert states[0] not in google_oauth._pending
    assert all(state in google_oauth._pending for state in states[1:])


class _FakeAsyncResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


class _CredentialErrorResponse(_FakeAsyncResponse):
    def raise_for_status(self):
        request = httpx.Request("POST", google_oauth.GOOGLE_TOKEN_URL)
        response = httpx.Response(400, request=request, json=self._data)
        raise httpx.HTTPStatusError("token request failed", request=request, response=response)


class _FakeAsyncClient:
    calls = []
    responses = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data):
        self.calls.append({"url": url, "data": data, "kwargs": self.kwargs})
        return self.responses.pop(0)


def test_exchange_and_refresh_payloads_and_expiry(monkeypatch):
    _FakeAsyncClient.calls = []
    _FakeAsyncClient.responses = [
        _FakeAsyncResponse(
            {
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "expires_in": 3600,
                "scope": google_oauth.CALDAV_SCOPE,
            }
        ),
        _FakeAsyncResponse(
            {
                "access_token": "access-2",
                "expires_in": 1800,
                "scope": google_oauth.CALDAV_SCOPE,
            }
        ),
    ]
    monkeypatch.setattr(google_oauth.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(google_oauth.time, "time", lambda: 1000.9)

    exchanged = asyncio.run(
        google_oauth.exchange_code("client", "secret", "code", "http://redirect")
    )
    refreshed = asyncio.run(
        google_oauth.refresh_access_token("client", "secret", "refresh-1")
    )

    assert exchanged == {
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "expires_at": 4540,
        "scope": google_oauth.CALDAV_SCOPE,
    }
    assert refreshed == {
        "access_token": "access-2",
        "expires_at": 2740,
        "scope": google_oauth.CALDAV_SCOPE,
    }
    assert _FakeAsyncClient.calls == [
        {
            "url": google_oauth.GOOGLE_TOKEN_URL,
            "data": {
                "client_id": "client",
                "client_secret": "secret",
                "code": "code",
                "grant_type": "authorization_code",
                "redirect_uri": "http://redirect",
            },
            "kwargs": {"timeout": 10.0, "trust_env": False},
        },
        {
            "url": google_oauth.GOOGLE_TOKEN_URL,
            "data": {
                "client_id": "client",
                "client_secret": "secret",
                "refresh_token": "refresh-1",
                "grant_type": "refresh_token",
            },
            "kwargs": {"timeout": 10.0, "trust_env": False},
        },
    ]


@pytest.mark.parametrize("error_code", ["invalid_grant", "invalid_client"])
def test_refresh_maps_invalid_credentials_to_reconnect_error(monkeypatch, error_code):
    _FakeAsyncClient.responses = [_CredentialErrorResponse({"error": error_code})]
    monkeypatch.setattr(google_oauth.httpx, "AsyncClient", _FakeAsyncClient)

    with pytest.raises(google_oauth.GoogleOAuthCredentialError) as error:
        asyncio.run(google_oauth.refresh_access_token("client", "secret", "refresh"))
    assert error.value.error_code == error_code


class _FakeReportResponse:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self._content = content

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        for offset in range(0, len(self._content), 4096):
            yield self._content[offset:offset + 4096]


class _FakeReportClient:
    calls = []
    response = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls.append({"kwargs": kwargs})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, method, url, **kwargs):
        self.calls[-1].update({"method": method, "url": url, **kwargs})
        return self.response


_REPORT_XML = b"""
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:response>
    <D:href>/caldav/v2/person@example.com/events/one</D:href>
    <D:propstat>
      <D:status>HTTP/1.1 404 Not Found</D:status>
      <D:prop><C:calendar-data/></D:prop>
    </D:propstat>
    <D:propstat>
      <D:status>HTTP/1.1 200 OK</D:status>
      <D:prop><C:calendar-data>BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:inline-1\nEND:VEVENT\nEND:VCALENDAR</C:calendar-data></D:prop>
    </D:propstat>
  </D:response>
</D:multistatus>
"""


def test_google_report_is_safe_and_reads_later_successful_propstat(monkeypatch):
    _FakeReportClient.calls = []
    _FakeReportClient.response = _FakeReportResponse(207, _REPORT_XML)
    monkeypatch.setattr(httpx, "Client", _FakeReportClient)

    url = "https://apidata.googleusercontent.com/caldav/v2/person@example.com/events"
    icals = caldav_sync._google_fetch_icals(
        "bearer-token", url, datetime(2026, 1, 1), datetime(2026, 1, 2)
    )

    assert icals == ["BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:inline-1\nEND:VEVENT\nEND:VCALENDAR"]
    call = _FakeReportClient.calls[0]
    assert call["kwargs"] == {"timeout": 30.0, "follow_redirects": False, "trust_env": False}
    assert call["method"] == "REPORT"
    assert call["url"] == url
    assert call["headers"]["Authorization"] == "Bearer bearer-token"
    assert b"calendar-query" in call["content"]


def test_google_report_rejects_failed_calendar_data_propstat(monkeypatch):
    response_xml = b"""
    <D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
      <D:response>
        <D:propstat>
          <D:status>HTTP/1.1 404 Not Found</D:status>
          <D:prop><C:calendar-data>missing</C:calendar-data></D:prop>
        </D:propstat>
      </D:response>
    </D:multistatus>
    """
    _FakeReportClient.calls = []
    _FakeReportClient.response = _FakeReportResponse(207, response_xml)
    monkeypatch.setattr(httpx, "Client", _FakeReportClient)

    with pytest.raises(RuntimeError, match="calendar-data"):
        caldav_sync._google_fetch_icals(
            "token",
            _GOOGLE_EVENTS,
            datetime(2026, 1, 1),
            datetime(2026, 1, 2),
        )


def test_google_report_rejects_response_missing_requested_calendar_data(monkeypatch):
    response_xml = b"""
    <D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
      <D:response>
        <D:propstat>
          <D:status>HTTP/1.1 404 Not Found</D:status>
          <D:prop><D:getetag>gone</D:getetag></D:prop>
        </D:propstat>
      </D:response>
    </D:multistatus>
    """
    _FakeReportClient.calls = []
    _FakeReportClient.response = _FakeReportResponse(207, response_xml)
    monkeypatch.setattr(httpx, "Client", _FakeReportClient)

    with pytest.raises(RuntimeError, match="calendar-data"):
        caldav_sync._google_fetch_icals(
            "token",
            _GOOGLE_EVENTS,
            datetime(2026, 1, 1),
            datetime(2026, 1, 2),
        )


def test_google_report_rejects_oversized_response_before_xml_parse(monkeypatch):
    _FakeReportClient.calls = []
    _FakeReportClient.response = _FakeReportResponse(207, b"x" * 11)
    monkeypatch.setattr(httpx, "Client", _FakeReportClient)
    monkeypatch.setattr(caldav_sync, "_GOOGLE_REPORT_MAX_BYTES", 10)

    with pytest.raises(RuntimeError, match="size limit"):
        caldav_sync._google_fetch_icals(
            "token",
            _GOOGLE_EVENTS,
            datetime(2026, 1, 1),
            datetime(2026, 1, 2),
        )


def test_google_report_serializes_explicit_utc_boundaries(monkeypatch):
    _FakeReportClient.calls = []
    _FakeReportClient.response = _FakeReportResponse(
        207,
        b'<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"/>',
    )
    monkeypatch.setattr(httpx, "Client", _FakeReportClient)

    caldav_sync._google_fetch_icals(
        "token",
        _GOOGLE_EVENTS,
        datetime(2025, 12, 31, 0, 30, tzinfo=timezone(timedelta(hours=2))),
        datetime(2026, 1, 1, 1, 0),
    )

    body = _FakeReportClient.calls[0]["content"]
    assert b'start="20251230T223000Z"' in body
    assert b'end="20260101T010000Z"' in body


class _FakeGoogleApiResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://www.googleapis.com/")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "Google API failure", request=request, response=response
            )

    def json(self):
        return self._data


class _FakeGoogleApiClient:
    calls = []
    responses = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return self.responses.pop(0)


def test_google_calendar_api_fetches_readonly_feeds_and_expands_recurrences(monkeypatch):
    _FakeGoogleApiClient.calls = []
    _FakeGoogleApiClient.responses = [
        _FakeGoogleApiResponse(
            {
                "items": [
                    {
                        "id": "holiday#calendar@example.com",
                        "summary": "Holidays",
                        "backgroundColor": "#16a765",
                    },
                    {"id": "person@example.com", "summary": "Personal"},
                ]
            }
        ),
        _FakeGoogleApiResponse(
            {
                "items": [
                    {
                        "id": "timed-event",
                        "summary": "Meeting",
                        "start": {
                            "dateTime": "2026-07-29T12:30:00",
                            "timeZone": "Europe/Zurich",
                        },
                        "end": {
                            "dateTime": "2026-07-29T13:30:00",
                            "timeZone": "Europe/Zurich",
                        },
                        "extendedProperties": {
                            "private": {
                                "odysseus_uid": "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"
                            }
                        },
                    },
                    {
                        "id": "cancelled-event",
                        "status": "cancelled",
                        "start": {"date": "2026-08-01"},
                        "end": {"date": "2026-08-02"},
                    },
                ]
            }
        ),
        _FakeGoogleApiResponse(
            {
                "items": [
                    {
                        "id": "all-day-event",
                        "summary": "Day off",
                        "start": {"date": "2026-08-01"},
                        "end": {"date": "2026-08-02"},
                    }
                ]
            }
        ),
    ]
    monkeypatch.setattr(httpx, "Client", _FakeGoogleApiClient)

    feeds = caldav_sync._google_fetch_calendar_feeds(
        "read-only-token",
        datetime(2026, 7, 1),
        datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert [feed.name for feed in feeds] == ["Holidays", "Personal"]
    assert feeds[0].color == "#16a765"
    assert "%23" in feeds[0].url
    assert len(feeds[0].icals) == 1
    assert len(feeds[1].icals) == 1
    assert "cancelled-event" not in feeds[0].icals[0]
    assert "UID:5b1d4e9c-9254-4edc-a9a2-e9136c67f098" in feeds[0].icals[0]
    assert feeds[0].resources[0].url.endswith("/events/timed-event")

    list_call, holiday_call, personal_call = _FakeGoogleApiClient.calls
    assert list_call["url"].endswith("/users/me/calendarList")
    assert holiday_call["url"].endswith(
        "/calendars/holiday%23calendar%40example.com/events"
    )
    assert personal_call["url"].endswith(
        "/calendars/person%40example.com/events"
    )
    assert holiday_call["params"]["singleEvents"] == "true"
    assert holiday_call["params"]["showDeleted"] == "true"
    assert holiday_call["params"]["timeMin"] == "2026-07-01T00:00:00Z"
    assert all(
        call["headers"]["Authorization"] == "Bearer read-only-token"
        for call in _FakeGoogleApiClient.calls
    )


def test_google_event_tolerates_malformed_private_properties():
    ical = caldav_sync._google_event_to_ical(
        "person@example.com",
        {
            "id": "event-1",
            "start": {"date": "2026-08-01"},
            "end": {"date": "2026-08-02"},
            "extendedProperties": {"private": ["not", "an", "object"]},
        },
    )

    expected_hash = hashlib.sha256(b"person@example.com").hexdigest()[:16]
    assert f"UID:google-{expected_hash}-event-1" in ical


def test_google_reconcile_series_keeps_master_and_moved_exception():
    preserved_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"
    master = {
        "id": "master",
        "summary": "Series",
        "start": {"dateTime": "2026-08-01T09:00:00+02:00"},
        "end": {"dateTime": "2026-08-01T10:00:00+02:00"},
        "recurrence": ["RRULE:FREQ=DAILY"],
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    regular = {
        "id": "master_20260802T070000Z",
        "recurringEventId": "master",
        "summary": "Series",
        "originalStartTime": {
            "dateTime": "2026-08-02T09:00:00+02:00"
        },
        "start": {"dateTime": "2026-08-02T09:00:00+02:00"},
        "end": {"dateTime": "2026-08-02T10:00:00+02:00"},
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    moved = {
        "id": "master_20260803T070000Z",
        "recurringEventId": "master",
        "summary": "Series moved",
        "originalStartTime": {
            "dateTime": "2026-08-03T09:00:00+02:00"
        },
        "start": {"dateTime": "2026-08-03T11:00:00+02:00"},
        "end": {"dateTime": "2026-08-03T12:00:00+02:00"},
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    _FakeGoogleApiClient.calls = []
    _FakeGoogleApiClient.responses = [_FakeGoogleApiResponse(master)]
    client = _FakeGoogleApiClient()

    reconciled = caldav_sync._google_reconcile_odysseus_series(
        client,
        {"Authorization": "Bearer token"},
        "person@example.com",
        [regular, moved],
    )

    assert [item["id"] for item in reconciled] == [
        "master",
        "master_20260803T070000Z",
    ]
    assert reconciled[0]["recurrence"] == [
        "RRULE:FREQ=DAILY",
        "EXDATE:20260803T070000Z",
    ]
    assert reconciled[1]["_odysseus_recurrence_exception"] is True
    master_ical = caldav_sync._google_event_to_ical(
        "person@example.com", reconciled[0]
    )
    assert "EXDATE:20260803T070000Z" in master_ical


def test_google_reconcile_series_preserves_instances_when_master_lookup_fails():
    preserved_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"
    instance = {
        "id": "master_20260802T070000Z",
        "recurringEventId": "master",
        "summary": "Series",
        "start": {"dateTime": "2026-08-02T09:00:00+02:00"},
        "end": {"dateTime": "2026-08-02T10:00:00+02:00"},
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    _FakeGoogleApiClient.responses = [
        _FakeGoogleApiResponse({}, status_code=503)
    ]

    reconciled = caldav_sync._google_reconcile_odysseus_series(
        _FakeGoogleApiClient(),
        {"Authorization": "Bearer token"},
        "person@example.com",
        [instance],
    )

    assert reconciled == [instance]


def test_google_duration_only_change_is_a_recurrence_exception():
    master = {
        "summary": "Series",
        "start": {"dateTime": "2026-08-01T09:00:00+02:00"},
        "end": {"dateTime": "2026-08-01T10:00:00+02:00"},
    }
    shortened = {
        "summary": "Series",
        "originalStartTime": {
            "dateTime": "2026-08-02T09:00:00+02:00"
        },
        "start": {"dateTime": "2026-08-02T09:00:00+02:00"},
        "end": {"dateTime": "2026-08-02T09:30:00+02:00"},
    }

    assert caldav_sync._google_instance_is_exception(shortened, master)


def test_google_exdate_merge_refreshes_only_current_sync_window():
    merged = caldav_sync._merge_google_recurrence_exdates(
        '["2026-05-01T07:00", "2026-08-03T07:00"]',
        ["2026-08-04T07:00"],
        datetime(2026, 7, 1),
        datetime(2027, 7, 1),
    )

    assert merged == ["2026-05-01T07:00", "2026-08-04T07:00"]


def test_google_unknown_timezone_is_reported_as_malformed_event():
    with pytest.raises(ValueError, match="unknown time zone"):
        caldav_sync._google_event_to_ical(
            "person@example.com",
            {
                "id": "bad-zone",
                "start": {
                    "dateTime": "2026-08-01T09:00:00",
                    "timeZone": "Legacy/Unknown",
                },
                "end": {
                    "dateTime": "2026-08-01T10:00:00",
                    "timeZone": "Legacy/Unknown",
                },
            },
        )


@pytest.mark.parametrize(
    "encoded_account",
    ["person%3Fexample.com", "person%23example.com", "person%2Fexample.com", "person%25example.com"],
)
def test_google_url_rejects_percent_encoded_delimiters(encoded_account):
    url = f"https://apidata.googleusercontent.com/caldav/v2/{encoded_account}/user"
    with pytest.raises(ValueError):
        caldav_sync.validate_google_caldav_url(url)


def test_google_url_normalizes_encoded_account_and_rejects_cross_account_target():
    encoded_principal = "https://apidata.googleusercontent.com/caldav/v2/person%40example.com/user"
    assert caldav_sync.validate_google_caldav_url(encoded_principal) == _GOOGLE_PRINCIPAL

    cross_account = "https://apidata.googleusercontent.com/caldav/v2/other%40example.com/events"
    with pytest.raises(ValueError, match="outside"):
        caldav_sync.validate_google_caldav_target(_GOOGLE_PRINCIPAL, cross_account)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("auth_type", "basic"),
        ("oauth_client_id", "changed-client"),
        ("oauth_client_secret", "enc:changed-secret"),
        ("oauth_refresh_token", "enc:changed-refresh"),
    ],
)
def test_refresh_does_not_write_after_delayed_account_mutation(
    monkeypatch, field, replacement
):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "",
        "oauth_expires_at": 0,
    }
    latest = dict(account)
    writes = []

    async def delayed_refresh(*args):
        latest[field] = replacement
        return {"access_token": "fresh", "expires_at": 2000}

    monkeypatch.setattr(google_oauth, "refresh_access_token", delayed_refresh)
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [latest])
    monkeypatch.setattr(
        caldav_sync,
        "save_caldav_accounts",
        lambda owner, accounts: writes.append((owner, accounts)),
    )

    with pytest.raises(RuntimeError, match="changed"):
        asyncio.run(caldav_sync.ensure_google_access_token("alice", "google-1", account))
    assert writes == []


def test_old_readonly_grant_requires_reconnect_before_token_use():
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": "https://www.googleapis.com/auth/calendar.readonly",
        "oauth_access_token": "unused",
        "oauth_expires_at": 9999999999,
    }

    with pytest.raises(ValueError, match="permissions changed"):
        asyncio.run(
            caldav_sync.ensure_google_access_token("alice", "google-1", account)
        )


def test_legacy_grant_without_scope_can_continue_pull_only(monkeypatch):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_access_token": "legacy-read-token",
        "oauth_expires_at": 9999999999,
    }

    token, _current = asyncio.run(
        caldav_sync.ensure_google_access_token(
            "alice",
            "google-1",
            account,
            require_write=False,
        )
    )

    assert token == "legacy-read-token"


def test_scope_helper_accepts_authoritative_multi_scope_response():
    granted = f"openid {google_oauth.CALDAV_SCOPE}"
    assert google_oauth.has_calendar_write_scope(granted)
    assert google_oauth.has_calendar_write_scope(google_oauth.CALENDAR_FULL_SCOPE)
    assert google_oauth.has_calendar_write_scope(
        f"{google_oauth.CALENDAR_EVENTS_SCOPE} "
        f"{google_oauth.CALENDAR_LIST_WRITE_SCOPE}"
    )
    assert google_oauth.has_calendar_write_scope(
        f"{google_oauth.CALENDAR_EVENTS_SCOPE} "
        f"{google_oauth.CALENDAR_READ_SCOPE}"
    )
    assert not google_oauth.has_calendar_write_scope(
        "https://www.googleapis.com/auth/calendar.readonly"
    )


def test_refresh_reduced_scope_clears_tokens_and_requires_reconnect(monkeypatch):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "enc:old-access",
        "oauth_expires_at": 0,
    }
    latest = dict(account)
    writes = []

    async def reduced_refresh(*args):
        return {
            "access_token": "readonly",
            "expires_at": 2000,
            "scope": "https://www.googleapis.com/auth/calendar.readonly",
        }

    monkeypatch.setattr(google_oauth, "refresh_access_token", reduced_refresh)
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [latest])
    monkeypatch.setattr(
        caldav_sync,
        "save_caldav_accounts",
        lambda owner, accounts: writes.append((owner, accounts)),
    )

    with pytest.raises(ValueError, match="permissions changed"):
        asyncio.run(
            caldav_sync.ensure_google_access_token("alice", "google-1", account)
        )
    saved = writes[0][1][0]
    assert saved["oauth_scope"].endswith("/calendar.readonly")
    assert saved["oauth_access_token"] == ""
    assert saved["oauth_refresh_token"] == ""
    assert saved["oauth_expires_at"] == 0


@pytest.mark.parametrize("error_code", ["invalid_grant", "invalid_client"])
def test_invalid_refresh_clears_tokens_only_for_matching_revision(
    monkeypatch, error_code
):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "enc:old-access",
        "oauth_expires_at": 0,
    }
    latest = dict(account)
    writes = []

    async def rejected_refresh(*args):
        raise google_oauth.GoogleOAuthCredentialError(error_code)

    monkeypatch.setattr(google_oauth, "refresh_access_token", rejected_refresh)
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [latest])
    monkeypatch.setattr(
        caldav_sync,
        "save_caldav_accounts",
        lambda owner, accounts: writes.append((owner, accounts)),
    )

    with pytest.raises(ValueError, match="reconnect"):
        asyncio.run(caldav_sync.ensure_google_access_token("alice", "google-1", account))
    assert writes and writes[0][1][0]["oauth_access_token"] == ""
    assert writes[0][1][0]["oauth_refresh_token"] == ""
    assert writes[0][1][0]["oauth_expires_at"] == 0


def test_invalid_refresh_does_not_clear_after_credential_revision_change(monkeypatch):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "enc:old-access",
        "oauth_expires_at": 0,
    }
    latest = dict(account, oauth_refresh_token="enc:rotated-by-user")
    writes = []

    async def rejected_refresh(*args):
        raise google_oauth.GoogleOAuthCredentialError("invalid_grant")

    monkeypatch.setattr(google_oauth, "refresh_access_token", rejected_refresh)
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [latest])
    monkeypatch.setattr(
        caldav_sync,
        "save_caldav_accounts",
        lambda owner, accounts: writes.append((owner, accounts)),
    )

    with pytest.raises(RuntimeError, match="changed"):
        asyncio.run(caldav_sync.ensure_google_access_token("alice", "google-1", account))
    assert writes == []
    assert latest["oauth_access_token"] == "enc:old-access"


def test_refresh_persists_rotated_refresh_token(monkeypatch):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "enc:old-access",
        "oauth_expires_at": 0,
    }
    latest = dict(account)
    writes = []

    async def rotated_refresh(*args):
        return {"access_token": "fresh", "refresh_token": "rotated", "expires_at": 2000}

    monkeypatch.setattr(google_oauth, "refresh_access_token", rotated_refresh)
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [latest])
    monkeypatch.setattr(
        caldav_sync,
        "save_caldav_accounts",
        lambda owner, accounts: writes.append((owner, accounts)),
    )

    access_token, _updated = asyncio.run(
        caldav_sync.ensure_google_access_token("alice", "google-1", account)
    )
    assert access_token == "fresh"
    assert writes[0][1][0]["oauth_refresh_token"] == "enc:rotated"


def test_refresh_persistence_failure_is_reported(monkeypatch):
    monkeypatch.setattr(secret_storage, "decrypt", lambda value: value or "")
    monkeypatch.setattr(secret_storage, "encrypt", lambda value: f"enc:{value}")
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "enc:old-access",
        "oauth_expires_at": 0,
    }

    async def successful_refresh(*args):
        return {"access_token": "fresh", "expires_at": 2000}

    def broken_save(*args):
        raise OSError("preferences unavailable")

    monkeypatch.setattr(google_oauth, "refresh_access_token", successful_refresh)
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [dict(account)])
    monkeypatch.setattr(caldav_sync, "save_caldav_accounts", broken_save)

    with pytest.raises(RuntimeError, match="persist"):
        asyncio.run(caldav_sync.ensure_google_access_token("alice", "google-1", account))


def test_sync_reports_corrupt_google_ciphertext_per_account(monkeypatch):
    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": google_oauth.CALDAV_SCOPE,
        "url": _GOOGLE_PRINCIPAL,
        "oauth_client_id": "client",
        "oauth_client_secret": "enc:secret",
        "oauth_refresh_token": "enc:refresh",
        "oauth_access_token": "enc:access",
        "oauth_expires_at": 0,
    }
    monkeypatch.setattr(caldav_sync, "_load_caldav_accounts", lambda owner: [account])

    def broken_decrypt(_value):
        raise RuntimeError("corrupt ciphertext")

    monkeypatch.setattr(secret_storage, "decrypt", broken_decrypt)
    result = asyncio.run(caldav_sync.sync_caldav("alice"))

    assert result["errors"]
    assert "invalid" in result["errors"][0].lower()


@pytest.mark.parametrize("status", [404, 500])
def test_google_report_failures_raise(monkeypatch, status):
    _FakeReportClient.calls = []
    _FakeReportClient.response = _FakeReportResponse(status)
    monkeypatch.setattr(httpx, "Client", _FakeReportClient)

    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        caldav_sync._google_fetch_icals(
            "token",
            "https://apidata.googleusercontent.com/caldav/v2/person@example.com/events",
            datetime(2026, 1, 1),
            datetime(2026, 1, 2),
        )


def test_google_report_rejects_unsafe_target_before_client_creation(monkeypatch):
    class _UnexpectedClient:
        def __init__(self, **kwargs):
            raise AssertionError("unsafe target reached HTTP client")

    monkeypatch.setattr(httpx, "Client", _UnexpectedClient)
    with pytest.raises(ValueError, match="target"):
        caldav_sync._google_fetch_icals(
            "token",
            "https://evil.example.test/caldav/v2/person@example.com/events",
            datetime(2026, 1, 1),
            datetime(2026, 1, 2),
        )


_GOOGLE_PRINCIPAL = "https://apidata.googleusercontent.com/caldav/v2/person@example.com/user"
_GOOGLE_EVENTS = "https://apidata.googleusercontent.com/caldav/v2/person@example.com/events"


def _sync_ics(uid="inline-sync"):
    stamp = (datetime.utcnow() + timedelta(days=2)).strftime("%Y%m%dT%H%M%SZ")
    return (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n"
        f"UID:{uid}\r\nDTSTART:{stamp}\r\nDTEND:{stamp}\r\n"
        "SUMMARY:Inline\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )


class _OAuthCalendar:
    url = _GOOGLE_EVENTS
    name = "Google"

    def date_search(self, *args, **kwargs):
        raise AssertionError("OAuth sync must not call date_search/per-event GET")


class _OAuthPrincipal:
    def calendars(self):
        return [_OAuthCalendar()]


class _OAuthClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.session = types.SimpleNamespace(max_redirects=30)

    def principal(self):
        return _OAuthPrincipal()

    def close(self):
        pass


class _BasicRemoteCalendar:
    url = "https://calendar.example.test/dav/events"
    name = "Basic"

    def __init__(self, not_found_error):
        self.not_found_error = not_found_error
        self.mode = "event"

    def date_search(self, *args, **kwargs):
        if self.mode == "missing":
            raise self.not_found_error("No events found")
        if self.mode == "partial":
            return [
                _BrokenCalendarObject(),
                types.SimpleNamespace(data=_sync_ics("basic-good")),
            ]
        return [types.SimpleNamespace(data=_sync_ics("basic-keep"))]


class _BrokenCalendarObject:
    @property
    def data(self):
        raise RuntimeError("unreadable event resource")


class _BasicPrincipal:
    def __init__(self, calendar):
        self.calendar = calendar

    def calendars(self):
        return [self.calendar]


class _BasicClient:
    def __init__(self, calendar):
        self.calendar = calendar

    def principal(self):
        return _BasicPrincipal(self.calendar)

    def close(self):
        pass


def _install_oauth_caldav(monkeypatch, session_factory):
    fake = types.ModuleType("caldav")
    fake.DAVClient = _OAuthClient
    errors = types.ModuleType("caldav.lib.error")
    errors.AuthorizationError = type("AuthorizationError", (Exception,), {})
    errors.NotFoundError = type("NotFoundError", (Exception,), {})
    lib = types.ModuleType("caldav.lib")
    lib.error = errors
    fake.lib = lib
    monkeypatch.setitem(sys.modules, "caldav", fake)
    monkeypatch.setitem(sys.modules, "caldav.lib", lib)
    monkeypatch.setitem(sys.modules, "caldav.lib.error", errors)
    monkeypatch.setattr(caldav_sync, "SessionLocal", session_factory, raising=False)
    monkeypatch.setattr(cdb, "SessionLocal", session_factory, raising=False)


def _clear_sync_db(session_factory):
    db = session_factory()
    try:
        db.query(CalendarEvent).delete()
        db.query(CalendarCal).delete()
        db.commit()
    finally:
        db.close()


@pytest.fixture
def sync_session(monkeypatch, tmp_path):
    """Isolated file-backed DB for the real import/prune path."""
    engine = create_engine(
        f"sqlite:///{tmp_path / 'google-oauth-caldav.db'}",
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )
    cdb.Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield session_factory
    engine.dispose()


def test_oauth_sync_imports_calendar_api_feed_without_dav_client(monkeypatch, sync_session):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    calls = []

    def fake_fetch(token, start, end):
        calls.append(token)
        return [
            caldav_sync._GoogleCalendarFeed(
                url=_GOOGLE_EVENTS,
                name="Google Calendar",
                color="#123456",
                icals=(_sync_ics(),),
            )
        ]

    monkeypatch.setattr(caldav_sync, "_google_fetch_calendar_feeds", fake_fetch)
    monkeypatch.setattr(
        caldav_sync,
        "_build_dav_client",
        lambda *args, **kwargs: pytest.fail("OAuth sync must not open a DAV client"),
    )
    result = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )

    assert result["events"] == 1, result
    assert not result["errors"], result
    assert calls == ["token"]
    db = sync_session()
    try:
        assert db.query(CalendarEvent).filter_by(uid="inline-sync").one().summary == "Inline"
        calendar = db.query(CalendarCal).one()
        assert calendar.name == "Google Calendar"
        assert calendar.color == "#123456"
    finally:
        db.close()


def test_oauth_sync_keeps_same_id_invitation_copies_as_distinct_events(
    monkeypatch, sync_session
):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    preserved_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"

    def event_item(event_id):
        return {
            "id": event_id,
            "summary": event_id,
            "start": {"date": "2026-08-01"},
            "end": {"date": "2026-08-02"},
            "extendedProperties": {
                "private": {"odysseus_uid": preserved_uid}
            },
        }

    def feed(calendar_id, event_id):
        calendar_hash = hashlib.sha256(
            calendar_id.encode("utf-8")
        ).hexdigest()[:16]
        encoded_calendar = calendar_id.replace("@", "%40")
        return caldav_sync._GoogleCalendarFeed(
            url=(
                "https://apidata.googleusercontent.com/caldav/v2/"
                f"{calendar_id}/events"
            ),
            name=calendar_id,
            color="#123456",
            icals=(
                caldav_sync._google_event_to_ical(
                    calendar_id, event_item(event_id)
                ),
            ),
            resources=(
                caldav_sync._GoogleEventResource(
                    url=(
                        "https://www.googleapis.com/calendar/v3/calendars/"
                        f"{encoded_calendar}/events/{event_id}"
                    ),
                    fallback_uid=f"google-{calendar_hash}-{event_id}",
                    odysseus_uid=preserved_uid,
                ),
            ),
        )

    monkeypatch.setattr(
        caldav_sync,
        "_google_fetch_calendar_feeds",
        lambda *args: [
            feed("person@example.com", "shared-id"),
            feed("team@example.com", "shared-id"),
        ],
    )

    result = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )

    assert result["events"] == 2, result
    assert not result["errors"], result
    copied_hash = hashlib.sha256(b"team@example.com").hexdigest()[:16]
    db = sync_session()
    try:
        assert {
            row.uid for row in db.query(CalendarEvent).all()
        } == {
            preserved_uid,
            f"google-{copied_hash}-shared-id",
        }
    finally:
        db.close()


def test_oauth_sync_migrates_legacy_caldav_href_without_rekeying(
    monkeypatch, sync_session
):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    preserved_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"
    local_calendar_id = caldav_sync._stable_cal_id(
        _GOOGLE_EVENTS, owner="alice", account_id="account"
    )
    legacy_href = (
        "https://apidata.googleusercontent.com/caldav/v2/"
        "person@example.com/events"
    )
    api_href = (
        "https://www.googleapis.com/calendar/v3/calendars/"
        "person%40example.com/events/event-1"
    )
    db = sync_session()
    try:
        db.add(
            CalendarCal(
                id=local_calendar_id,
                owner="alice",
                name="Google Calendar",
                source="caldav",
                account_id="account",
                caldav_base_url=_GOOGLE_EVENTS,
            )
        )
        db.add(
            CalendarEvent(
                uid=preserved_uid,
                calendar_id=local_calendar_id,
                summary="Legacy",
                dtstart=datetime(2026, 8, 1),
                dtend=datetime(2026, 8, 2),
                all_day=True,
                origin="caldav",
                remote_href=legacy_href,
            )
        )
        db.commit()
    finally:
        db.close()

    item = {
        "id": "event-1",
        "summary": "Migrated",
        "start": {"date": "2026-08-01"},
        "end": {"date": "2026-08-02"},
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    monkeypatch.setattr(
        caldav_sync,
        "_google_fetch_calendar_feeds",
        lambda *args: [
            caldav_sync._GoogleCalendarFeed(
                url=_GOOGLE_EVENTS,
                name="Google Calendar",
                color="#123456",
                icals=(
                    caldav_sync._google_event_to_ical(
                        "person@example.com", item
                    ),
                ),
                resources=(
                    caldav_sync._GoogleEventResource(
                        url=api_href,
                        fallback_uid="google-fallback-event-1",
                        odysseus_uid=preserved_uid,
                    ),
                ),
            )
        ],
    )

    result = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )

    assert result["events"] == 1
    assert not result["errors"]
    db = sync_session()
    try:
        rows = db.query(CalendarEvent).all()
        assert [row.uid for row in rows] == [preserved_uid]
        assert rows[0].summary == "Migrated"
        assert rows[0].remote_href == api_href
    finally:
        db.close()


def test_oauth_sync_google_move_keeps_stable_odysseus_uid(
    monkeypatch, sync_session
):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    preserved_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"
    source_url = (
        "https://apidata.googleusercontent.com/caldav/v2/"
        "source@example.com/events"
    )
    destination_url = (
        "https://apidata.googleusercontent.com/caldav/v2/"
        "destination@example.com/events"
    )
    source_calendar_id = caldav_sync._stable_cal_id(
        source_url, owner="alice", account_id="account"
    )
    destination_calendar_id = caldav_sync._stable_cal_id(
        destination_url, owner="alice", account_id="account"
    )
    source_href = (
        "https://www.googleapis.com/calendar/v3/calendars/"
        "source%40example.com/events/same-google-id"
    )
    destination_href = (
        "https://www.googleapis.com/calendar/v3/calendars/"
        "destination%40example.com/events/same-google-id"
    )
    db = sync_session()
    try:
        db.add(
            CalendarCal(
                id=source_calendar_id,
                owner="alice",
                name="Source",
                source="caldav",
                account_id="account",
                caldav_base_url=source_url,
            )
        )
        db.add(
            CalendarEvent(
                uid=preserved_uid,
                calendar_id=source_calendar_id,
                summary="Before move",
                dtstart=datetime(2026, 8, 1),
                dtend=datetime(2026, 8, 2),
                all_day=True,
                origin="caldav",
                remote_href=source_href,
            )
        )
        db.commit()
    finally:
        db.close()

    moved = {
        "id": "same-google-id",
        "summary": "After move",
        "start": {"date": "2026-08-01"},
        "end": {"date": "2026-08-02"},
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    monkeypatch.setattr(
        caldav_sync,
        "_google_fetch_calendar_feeds",
        lambda *args: [
            caldav_sync._GoogleCalendarFeed(
                url=destination_url,
                name="Destination",
                color="#123456",
                icals=(
                    caldav_sync._google_event_to_ical(
                        "destination@example.com", moved
                    ),
                ),
                resources=(
                    caldav_sync._GoogleEventResource(
                        url=destination_href,
                        fallback_uid="google-fallback",
                        odysseus_uid=preserved_uid,
                    ),
                ),
            )
        ],
    )

    result = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )

    assert result["events"] == 1
    assert not result["errors"]
    db = sync_session()
    try:
        row = db.query(CalendarEvent).one()
        assert row.uid == preserved_uid
        assert row.calendar_id == destination_calendar_id
        assert row.remote_href == destination_href
    finally:
        db.close()


def test_oauth_sync_does_not_duplicate_local_recurring_master_instances(
    monkeypatch, sync_session
):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    preserved_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"
    calendar_id = "person@example.com"
    local_calendar_id = caldav_sync._stable_cal_id(
        _GOOGLE_EVENTS, owner="alice", account_id="account"
    )
    db = sync_session()
    try:
        calendar = CalendarCal(
            id=local_calendar_id,
            owner="alice",
            name="Google Calendar",
            source="caldav",
            account_id="account",
            caldav_base_url=_GOOGLE_EVENTS,
        )
        master = CalendarEvent(
            uid=preserved_uid,
            calendar_id=local_calendar_id,
            summary="Local series",
            dtstart=datetime(2026, 8, 1, 9, 0),
            dtend=datetime(2026, 8, 1, 10, 0),
            rrule="FREQ=DAILY",
            origin=None,
            remote_href=(
                "https://www.googleapis.com/calendar/v3/calendars/"
                "person%40example.com/events/master"
            ),
        )
        db.add(calendar)
        db.add(master)
        db.commit()
    finally:
        db.close()

    google_master = {
        "id": "master",
        "summary": "Google series",
        "start": {
            "dateTime": "2026-08-01T11:00:00+02:00",
            "timeZone": "Europe/Zurich",
        },
        "end": {
            "dateTime": "2026-08-01T12:00:00+02:00",
            "timeZone": "Europe/Zurich",
        },
        "recurrence": [
            "RRULE:FREQ=DAILY",
            "EXDATE:20260803T070000Z",
        ],
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    instance = {
        "id": "master_20260802T070000Z",
        "recurringEventId": "master",
        "summary": "Local series",
        "start": {"dateTime": "2026-08-02T09:00:00+02:00"},
        "end": {"dateTime": "2026-08-02T10:00:00+02:00"},
        "extendedProperties": {
            "private": {"odysseus_uid": preserved_uid}
        },
    }
    instance_hash = hashlib.sha256(calendar_id.encode()).hexdigest()[:16]
    monkeypatch.setattr(
        caldav_sync,
        "_google_fetch_calendar_feeds",
        lambda *args: [
            caldav_sync._GoogleCalendarFeed(
                url=_GOOGLE_EVENTS,
                name="Google Calendar",
                color="#123456",
                icals=(
                    caldav_sync._google_event_to_ical(
                        calendar_id, google_master
                    ),
                    caldav_sync._google_event_to_ical(calendar_id, instance),
                ),
                resources=(
                    caldav_sync._GoogleEventResource(
                        url=(
                            "https://www.googleapis.com/calendar/v3/calendars/"
                            "person%40example.com/events/master"
                        ),
                        fallback_uid=f"google-{instance_hash}-master",
                        odysseus_uid=preserved_uid,
                        timezone="Europe/Zurich",
                    ),
                    caldav_sync._GoogleEventResource(
                        url=(
                            "https://www.googleapis.com/calendar/v3/calendars/"
                            "person%40example.com/events/"
                            "master_20260802T070000Z"
                        ),
                        fallback_uid=(
                            f"google-{instance_hash}-"
                            "master_20260802T070000Z"
                        ),
                        odysseus_uid=preserved_uid,
                        recurring_instance=True,
                    ),
                ),
            )
        ],
    )

    result = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )

    assert not result["errors"], result
    db = sync_session()
    try:
        rows = db.query(CalendarEvent).all()
        assert [row.uid for row in rows] == [preserved_uid]
        assert rows[0].summary == "Google series"
        assert rows[0].dtstart == datetime(2026, 8, 1, 9, 0)
        assert rows[0].timezone_name == "Europe/Zurich"
        assert rows[0].rrule == "FREQ=DAILY"
        assert rows[0].recurrence_exdates == '["2026-08-03T07:00"]'
    finally:
        db.close()


def test_oauth_api_failure_does_not_prune_cached_event(monkeypatch, sync_session):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    monkeypatch.setattr(
        caldav_sync,
        "_google_fetch_calendar_feeds",
        lambda *args: [
            caldav_sync._GoogleCalendarFeed(
                url=_GOOGLE_EVENTS,
                name="Google Calendar",
                color="#123456",
                icals=(_sync_ics("keep-me"),),
            )
        ],
    )
    first = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )
    assert first["events"] == 1, first

    def failed_api(*args):
        raise RuntimeError("Calendar API returned HTTP 503")

    monkeypatch.setattr(caldav_sync, "_google_fetch_calendar_feeds", failed_api)
    second = caldav_sync._sync_blocking(
        "alice", _GOOGLE_PRINCIPAL, account_id="account", access_token="token"
    )

    assert second["deleted"] == 0, second
    assert any("Google Calendar API failed" in error for error in second["errors"])
    db = sync_session()
    try:
        assert db.query(CalendarEvent).filter_by(uid="keep-me").one() is not None
    finally:
        db.close()


def test_basic_no_events_not_found_does_not_prune_cached_event(monkeypatch, sync_session):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    not_found_error = sys.modules["caldav.lib.error"].NotFoundError
    remote_calendar = _BasicRemoteCalendar(not_found_error)
    monkeypatch.setattr(
        caldav_sync,
        "_build_dav_client",
        lambda *args, **kwargs: _BasicClient(remote_calendar),
    )

    first = caldav_sync._sync_blocking(
        "alice",
        "https://calendar.example.test/dav",
        "user",
        "password",
        "basic-account",
    )
    assert first["events"] == 1, first

    remote_calendar.mode = "missing"
    second = caldav_sync._sync_blocking(
        "alice",
        "https://calendar.example.test/dav",
        "user",
        "password",
        "basic-account",
    )

    assert second["deleted"] == 0, second
    assert not second["errors"], second
    db = sync_session()
    try:
        assert db.query(CalendarEvent).filter_by(uid="basic-keep").one() is not None
    finally:
        db.close()


def test_basic_unreadable_object_does_not_block_other_events(monkeypatch, sync_session):
    _install_oauth_caldav(monkeypatch, sync_session)
    _clear_sync_db(sync_session)
    not_found_error = sys.modules["caldav.lib.error"].NotFoundError
    remote_calendar = _BasicRemoteCalendar(not_found_error)
    remote_calendar.mode = "partial"
    monkeypatch.setattr(
        caldav_sync,
        "_build_dav_client",
        lambda *args, **kwargs: _BasicClient(remote_calendar),
    )

    result = caldav_sync._sync_blocking(
        "alice",
        "https://calendar.example.test/dav",
        "user",
        "password",
        "basic-account",
    )

    assert result["events"] == 1, result
    assert any("unreadable event resource" in error for error in result["errors"])
    db = sync_session()
    try:
        assert db.query(CalendarEvent).filter_by(uid="basic-good").one() is not None
    finally:
        db.close()
