"""Issue #800 — CalDAV write-back pushes local changes to the remote server.

Unit-tests the pure pieces against a fake caldav calendar (no network): the
iCalendar serialization, hash-based remote-calendar discovery, and the
create/update/delete orchestration.
"""

import asyncio
import sys
import types
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx
import pytest

from src.caldav_writeback import (
    _google_writeback_blocking,
    build_event_ical,
    find_remote_calendar,
    push_event,
    _stable_cal_id,
)

REMOTE_URL = "https://p69-caldav.icloud.com/123/calendars/home/"
CAL_ID = _stable_cal_id(REMOTE_URL)


class FakeEvent:
    def __init__(self, url="https://p69-caldav.icloud.com/123/calendars/home/evt-1.ics"):
        self.url = url
        self.etag = '"abc123"'
        self.data = "OLD"
        self.saved = False
        self.deleted = False

    def save(self):
        self.saved = True

    def delete(self):
        self.deleted = True


class FakeCalendar:
    def __init__(self, url, existing=None):
        self.url = url
        self._existing = existing
        self.saved_ical = None
        self.created = FakeEvent(str(url).rstrip("/") + "/created.ics")

    def event_by_uid(self, uid):
        if self._existing is None:
            raise Exception("not found")
        return self._existing

    def save_event(self, ical):
        self.saved_ical = ical
        return self.created


def _ev(**over):
    base = dict(
        uid="evt-1", summary="Dentist", description="bring x-rays",
        location="Clinic", dtstart=datetime(2026, 6, 10, 14, 0),
        dtend=datetime(2026, 6, 10, 15, 0), all_day=False, is_utc=True, rrule="",
    )
    base.update(over)
    return base


def _session_factory_with_calendar(row):
    class _Query:
        def filter(self, *args):
            return self

        def first(self):
            return row

    class _Session:
        def query(self, *args):
            return _Query()

        def close(self):
            pass

    return _Session


def test_build_ical_timed_event_has_core_fields():
    ical = build_event_ical(_ev())
    assert "BEGIN:VEVENT" in ical and "END:VEVENT" in ical
    assert "UID:evt-1" in ical
    assert "SUMMARY:Dentist" in ical
    # is_utc -> UTC instant (Z suffix)
    assert "DTSTART:20260610T140000Z" in ical
    assert "DTEND:20260610T150000Z" in ical


def test_build_ical_all_day_uses_date_values():
    ical = build_event_ical(_ev(all_day=True, is_utc=False))
    assert "DTSTART;VALUE=DATE:20260610" in ical


def test_build_ical_includes_rrule():
    ical = build_event_ical(_ev(rrule="FREQ=WEEKLY;BYDAY=MO"))
    assert "RRULE:FREQ=WEEKLY" in ical


def test_find_remote_calendar_matches_by_hash():
    cals = [FakeCalendar("https://other/x/"), FakeCalendar(REMOTE_URL)]
    found = find_remote_calendar(cals, CAL_ID)
    assert found is cals[1]
    assert find_remote_calendar([FakeCalendar("https://nope/")], CAL_ID) is None


def test_push_create_calls_save_event():
    cal = FakeCalendar(REMOTE_URL, existing=None)  # event_by_uid raises -> create
    res = push_event([cal], CAL_ID, _ev(), delete=False)
    assert res["ok"] and res.get("created")
    assert cal.saved_ical and "UID:evt-1" in cal.saved_ical
    assert res["calendar_url"] == REMOTE_URL
    assert res["remote_href"].endswith("/created.ics")


def test_push_update_overwrites_existing():
    existing = FakeEvent()
    cal = FakeCalendar(REMOTE_URL, existing=existing)
    res = push_event([cal], CAL_ID, _ev(summary="Moved"), delete=False)
    assert res["ok"] and res.get("updated")
    assert existing.saved and "SUMMARY:Moved" in existing.data
    assert cal.saved_ical is None  # used update path, not create
    assert res["remote_href"].endswith("evt-1.ics")
    assert res["remote_etag"] == '"abc123"'


def test_push_delete_removes_existing():
    existing = FakeEvent()
    cal = FakeCalendar(REMOTE_URL, existing=existing)
    res = push_event([cal], CAL_ID, _ev(), delete=True)
    assert res["ok"] and existing.deleted


def test_push_delete_absent_is_ok():
    cal = FakeCalendar(REMOTE_URL, existing=None)
    res = push_event([cal], CAL_ID, _ev(), delete=True)
    assert res["ok"] and "absent" in res.get("note", "")


def test_push_unknown_calendar_reports_not_found():
    cal = FakeCalendar("https://different/")
    res = push_event([cal], CAL_ID, _ev())
    assert res["ok"] is False and "not found" in res["error"]


def test_push_missing_uid_reports_input_error_before_remote_lookup():
    cal = FakeCalendar(REMOTE_URL, existing=FakeEvent())
    res = push_event([cal], CAL_ID, _ev(uid=""))
    assert res["ok"] is False and "uid" in res["error"]
    assert cal._existing.saved is False


def test_writeback_validates_saved_url_before_remote_call(monkeypatch):
    import core.database as cdb
    import src.caldav_sync as sync
    import src.caldav_writeback as wb

    prefs_mod = types.ModuleType("routes.prefs_routes")
    prefs_mod._load_for_user = lambda owner: {
        "caldav": {
            "url": " https://dav.example.com/calendars/home/ ",
            "username": owner,
            "password": "enc:pw",
        }
    }
    secret_mod = types.ModuleType("src.secret_storage")
    secret_mod.decrypt = lambda value: "plain-password"
    monkeypatch.setitem(sys.modules, "routes.prefs_routes", prefs_mod)
    monkeypatch.setitem(sys.modules, "src.secret_storage", secret_mod)

    captured = {}

    def fake_validate(url):
        captured["validated_url"] = url
        return "https://dav.example.com/calendars/home"

    def fake_writeback_blocking(local_cal_id, ev, delete, url, username, password,
                                owner="", account_id=""):
        captured.update(
            {
                "local_cal_id": local_cal_id,
                "delete": delete,
                "url": url,
                "username": username,
                "password": password,
            }
        )
        return {"ok": True}

    monkeypatch.setattr(sync, "validate_caldav_url", fake_validate)
    monkeypatch.setattr(
        cdb,
        "SessionLocal",
        _session_factory_with_calendar(
            types.SimpleNamespace(account_id=None, caldav_base_url=None)
        ),
    )
    monkeypatch.setattr(wb, "_writeback_blocking", fake_writeback_blocking)
    monkeypatch.setattr(
        wb, "_persist_writeback_result", lambda *args, **kwargs: None
    )

    result = asyncio.run(
        wb.writeback_event("alice", "caldav", "caldav-123", {"uid": "evt-1"})
    )

    assert result == {"ok": True}
    assert captured == {
        "validated_url": "https://dav.example.com/calendars/home/",
        "local_cal_id": "caldav-123",
        "delete": False,
        "url": "https://dav.example.com/calendars/home",
        "username": "alice",
        "password": "plain-password",
    }


def test_writeback_rejects_unsafe_saved_url_before_remote_call(monkeypatch):
    import core.database as cdb
    import src.caldav_sync as sync
    import src.caldav_writeback as wb

    prefs_mod = types.ModuleType("routes.prefs_routes")
    prefs_mod._load_for_user = lambda owner: {
        "caldav": {
            "url": "http://evil.example/latest/meta-data",
            "username": owner,
            "password": "enc:pw",
        }
    }
    secret_mod = types.ModuleType("src.secret_storage")
    secret_mod.decrypt = lambda value: "plain-password"
    monkeypatch.setitem(sys.modules, "routes.prefs_routes", prefs_mod)
    monkeypatch.setitem(sys.modules, "src.secret_storage", secret_mod)

    called = False

    def fake_validate(_url):
        raise ValueError("CalDAV URL host is not allowed")

    def fake_writeback_blocking(local_cal_id, ev, delete, url, username, password,
                                owner="", account_id=""):
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(sync, "validate_caldav_url", fake_validate)
    monkeypatch.setattr(
        cdb,
        "SessionLocal",
        _session_factory_with_calendar(
            types.SimpleNamespace(account_id=None, caldav_base_url=None)
        ),
    )
    monkeypatch.setattr(wb, "_writeback_blocking", fake_writeback_blocking)
    monkeypatch.setattr(
        wb, "_persist_writeback_result", lambda *args, **kwargs: None
    )

    result = asyncio.run(
        wb.writeback_event("alice", "caldav", "caldav-123", {"uid": "evt-1"})
    )

    assert result == {"ok": False, "error": "CalDAV URL host is not allowed"}
    assert called is False


class _GoogleResponse:
    def __init__(self, status_code=200, data=None, headers=None):
        self.status_code = status_code
        self._data = data or {}
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://www.googleapis.com/")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "Google write failed", request=request, response=response
            )

    def json(self):
        return self._data


class _GoogleClient:
    calls = []
    responses = []
    init_kwargs = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.init_kwargs.append(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _call(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        return self._call("POST", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._call("PATCH", url, **kwargs)

    def get(self, url, **kwargs):
        return self._call("GET", url, **kwargs)

    def delete(self, url, **kwargs):
        return self._call("DELETE", url, **kwargs)


@pytest.fixture(autouse=True)
def reset_google_client_state():
    _GoogleClient.calls = []
    _GoogleClient.responses = []
    _GoogleClient.init_kwargs = []
    yield
    _GoogleClient.calls = []
    _GoogleClient.responses = []
    _GoogleClient.init_kwargs = []


_GOOGLE_COLLECTION = (
    "https://apidata.googleusercontent.com/caldav/v2/"
    "person@example.com/events"
)


def test_google_writeback_creates_event_and_preserves_local_uid(monkeypatch):
    _GoogleClient.calls = []
    _GoogleClient.init_kwargs = []
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "remote-1", "etag": '"etag-1"'})
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    local_uid = "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"

    result = _google_writeback_blocking(
        _ev(uid=local_uid),
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["ok"] and result["created"]
    assert result["remote_href"].endswith("/events/remote-1")
    call = _GoogleClient.calls[0]
    assert call["method"] == "POST"
    assert call["headers"]["Authorization"] == "Bearer write-token"
    assert call["json"]["start"]["dateTime"] == "2026-06-10T14:00:00Z"
    assert call["json"]["recurrence"] == []
    assert call["json"]["extendedProperties"]["private"]["odysseus_uid"] == local_uid
    assert _GoogleClient.init_kwargs == [
        {"timeout": 30.0, "follow_redirects": False, "trust_env": False}
    ]


def test_google_writeback_patches_and_deletes_specific_remote_event(monkeypatch):
    _GoogleClient.calls = []
    _GoogleClient.init_kwargs = []
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "remote-1", "etag": '"etag-2"'}),
        _GoogleResponse(204),
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    event = _ev(
        uid="google-542d240129883c01-remote-1",
        remote_href=(
            "https://www.googleapis.com/calendar/v3/calendars/"
            "person%40example.com/events/remote-1"
        ),
        remote_etag='"etag-1"',
    )

    updated = _google_writeback_blocking(
        event, False, _GOOGLE_COLLECTION, "write-token"
    )
    deleted = _google_writeback_blocking(
        event, True, _GOOGLE_COLLECTION, "write-token"
    )

    assert updated["ok"] and updated["updated"]
    assert deleted["ok"]
    assert [call["method"] for call in _GoogleClient.calls] == ["PATCH", "DELETE"]
    assert all(
        call["url"].endswith("/events/remote-1")
        for call in _GoogleClient.calls
    )
    assert all(
        call["headers"]["If-Match"] == '"etag-1"'
        for call in _GoogleClient.calls
    )


def test_google_writeback_preserves_local_timezone_and_recurrence_exdates(
    monkeypatch,
):
    import src.caldav_writeback as wb

    _GoogleClient.calls = []
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "remote-1", "etag": '"etag-1"'})
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    monkeypatch.setattr(wb, "_host_timezone_name", lambda: "Europe/Zurich")

    result = _google_writeback_blocking(
        _ev(
            uid="5b1d4e9c-9254-4edc-a9a2-e9136c67f098",
            is_utc=False,
            rrule="FREQ=WEEKLY;BYDAY=WE",
            recurrence_exdates=["2026-07-08T14:00"],
        ),
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["ok"]
    body = _GoogleClient.calls[0]["json"]
    assert body["start"] == {
        "dateTime": "2026-06-10T14:00:00",
        "timeZone": "Europe/Zurich",
    }
    assert body["recurrence"] == [
        "RRULE:FREQ=WEEKLY;BYDAY=WE",
        "EXDATE;TZID=Europe/Zurich:20260708T140000",
    ]


def test_google_writeback_rejects_floating_time_when_zone_is_unknown(
    monkeypatch,
):
    import src.caldav_writeback as wb

    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    monkeypatch.setattr(wb, "_host_timezone_name", lambda: "")

    with pytest.raises(ValueError, match="timezone is required"):
        _google_writeback_blocking(
            _ev(is_utc=False),
            False,
            _GOOGLE_COLLECTION,
            "write-token",
        )


def test_google_writeback_sets_utc_timezone_for_recurring_utc_event(
    monkeypatch,
):
    _GoogleClient.calls = []
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "remote-1", "etag": '"etag-1"'})
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)

    result = _google_writeback_blocking(
        _ev(rrule="FREQ=DAILY"),
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["ok"]
    body = _GoogleClient.calls[0]["json"]
    assert body["start"]["timeZone"] == "UTC"
    assert body["end"]["timeZone"] == "UTC"


def test_google_writeback_reuses_aware_event_zone_for_recurrence(
    monkeypatch,
):
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "remote-1", "etag": '"etag-1"'})
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    new_york = ZoneInfo("America/New_York")

    result = _google_writeback_blocking(
        _ev(
            dtstart=datetime(2026, 6, 10, 14, 0, tzinfo=new_york),
            dtend=datetime(2026, 6, 10, 15, 0, tzinfo=new_york),
            is_utc=False,
            rrule="FREQ=WEEKLY",
            recurrence_exdates=["2026-07-08T14:00"],
        ),
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["ok"]
    body = _GoogleClient.calls[0]["json"]
    assert body["start"]["timeZone"] == "America/New_York"
    assert body["end"]["timeZone"] == "America/New_York"
    assert body["recurrence"][1].startswith(
        "EXDATE;TZID=America/New_York:"
    )


def test_google_writeback_preserves_imported_recurring_master_timezone(
    monkeypatch,
):
    _GoogleClient.responses = [
        _GoogleResponse(
            200,
            {
                "id": "master-1",
                "start": {
                    "dateTime": "2026-06-10T09:00:00+02:00",
                    "timeZone": "Europe/Zurich",
                },
            },
        ),
        _GoogleResponse(200, {"id": "master-1", "etag": '"saved"'}),
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    event = _ev(
        uid="google-542d240129883c01-master-1",
        dtstart=datetime(2026, 6, 10, 7, 0),
        dtend=datetime(2026, 6, 10, 8, 0),
        is_utc=True,
        rrule="FREQ=WEEKLY",
        remote_href=(
            "https://www.googleapis.com/calendar/v3/calendars/"
            "person%40example.com/events/master-1"
        ),
    )

    result = _google_writeback_blocking(
        event, False, _GOOGLE_COLLECTION, "write-token"
    )

    assert result["ok"] and result["updated"]
    assert [call["method"] for call in _GoogleClient.calls] == ["GET", "PATCH"]
    body = _GoogleClient.calls[1]["json"]
    assert body["start"] == {
        "dateTime": "2026-06-10T09:00:00+02:00",
        "timeZone": "Europe/Zurich",
    }
    assert body["end"] == {
        "dateTime": "2026-06-10T10:00:00+02:00",
        "timeZone": "Europe/Zurich",
    }


def test_google_writeback_defaults_missing_all_day_end_to_next_day(
    monkeypatch,
):
    _GoogleClient.calls = []
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "remote-1", "etag": '"etag-1"'})
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)

    result = _google_writeback_blocking(
        _ev(all_day=True, is_utc=False, dtend=None),
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["ok"]
    body = _GoogleClient.calls[0]["json"]
    assert body["start"] == {"date": "2026-06-10"}
    assert body["end"] == {"date": "2026-06-11"}


def test_google_writeback_rejects_missing_start_with_clear_error(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    with pytest.raises(ValueError, match="start is required"):
        _google_writeback_blocking(
            {"uid": "5b1d4e9c-9254-4edc-a9a2-e9136c67f098"},
            False,
            _GOOGLE_COLLECTION,
            "write-token",
        )


def test_google_uid_from_another_calendar_does_not_select_remote_event(
    monkeypatch,
):
    _GoogleClient.calls = []
    _GoogleClient.responses = [
        _GoogleResponse(200, {"id": "new-event", "etag": '"etag-new"'})
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)

    result = _google_writeback_blocking(
        _ev(uid="google-0000000000000000-other-calendar-event"),
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["created"]
    assert _GoogleClient.calls[0]["method"] == "POST"
    assert _GoogleClient.calls[0]["url"].endswith(
        "/calendars/person%40example.com/events"
    )


def test_google_patch_missing_remote_event_recreates_it(monkeypatch):
    _GoogleClient.calls = []
    _GoogleClient.responses = [
        _GoogleResponse(410),
        _GoogleResponse(200, {"id": "replacement", "etag": '"new"'}),
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    event = _ev(
        remote_href=(
            "https://www.googleapis.com/calendar/v3/calendars/"
            "person%40example.com/events/missing"
        ),
        remote_etag='"old"',
    )

    result = _google_writeback_blocking(
        event, False, _GOOGLE_COLLECTION, "write-token"
    )

    assert result["created"] and not result["updated"]
    assert [call["method"] for call in _GoogleClient.calls] == ["PATCH", "POST"]
    assert "If-Match" not in _GoogleClient.calls[1]["headers"]


def test_google_patch_reports_stale_etag_without_overwriting_remote_change(
    monkeypatch,
):
    _GoogleClient.calls = []
    _GoogleClient.responses = [_GoogleResponse(412)]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    event = _ev(
        remote_href=(
            "https://www.googleapis.com/calendar/v3/calendars/"
            "person%40example.com/events/remote-1"
        ),
        remote_etag='"stale"',
    )

    result = _google_writeback_blocking(
        event, False, _GOOGLE_COLLECTION, "write-token"
    )

    assert result["ok"] is False
    assert result["conflict"] is True
    assert [call["method"] for call in _GoogleClient.calls] == ["PATCH"]
    assert _GoogleClient.calls[0]["headers"]["If-Match"] == '"stale"'


def test_google_recurring_instance_patch_omits_recurrence_array(monkeypatch):
    _GoogleClient.responses = [
        _GoogleResponse(
            200,
            {
                "id": "master_20260802T070000Z",
                "recurringEventId": "master",
            },
        ),
        _GoogleResponse(
            200,
            {
                "id": "master_20260802T070000Z",
                "etag": '"saved"',
            },
        )
    ]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    event = _ev(
        remote_href=(
            "https://www.googleapis.com/calendar/v3/calendars/"
            "person%40example.com/events/master_20260802T070000Z"
        ),
        remote_etag='"current"',
    )

    result = _google_writeback_blocking(
        event, False, _GOOGLE_COLLECTION, "write-token"
    )

    assert result["ok"] and result["updated"]
    assert [call["method"] for call in _GoogleClient.calls] == ["GET", "PATCH"]
    assert "recurrence" not in _GoogleClient.calls[1]["json"]


def test_google_delete_treats_gone_as_already_absent(monkeypatch):
    _GoogleClient.calls = []
    _GoogleClient.responses = [_GoogleResponse(410)]
    monkeypatch.setattr(httpx, "Client", _GoogleClient)
    event = _ev(
        remote_href=(
            "https://www.googleapis.com/calendar/v3/calendars/"
            "person%40example.com/events/remote-1"
        )
    )

    result = _google_writeback_blocking(
        event, True, _GOOGLE_COLLECTION, "write-token"
    )

    assert result["ok"] and "absent" in result["note"]


def test_google_delete_without_resolvable_remote_id_reports_failure(
    monkeypatch,
):
    monkeypatch.setattr(httpx, "Client", _GoogleClient)

    result = _google_writeback_blocking(
        _ev(uid="local-uid", remote_href=""),
        True,
        _GOOGLE_COLLECTION,
        "write-token",
    )

    assert result["ok"] is False
    assert "id is unavailable" in result["error"]


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/caldav/v2/person@example.com/events",
        "http://apidata.googleusercontent.com/caldav/v2/person@example.com/events",
        "https://apidata.googleusercontent.com/caldav/v2/person@example.com/user",
    ],
)
def test_google_writeback_rejects_unpinned_calendar_collection(url):
    with pytest.raises(ValueError, match="collection URL"):
        _google_writeback_blocking(_ev(), False, url, "token")


def test_writeback_event_routes_google_account_through_oauth_api(monkeypatch):
    import core.database as cdb
    import src.caldav_sync as sync
    import src.caldav_writeback as wb
    from src.google_oauth import CALDAV_SCOPE

    calendar_row = types.SimpleNamespace(
        id="caldav-google",
        owner="alice",
        account_id="google-1",
        caldav_base_url=_GOOGLE_COLLECTION,
    )

    class _Query:
        def filter(self, *args):
            return self

        def first(self):
            return calendar_row

    class _Session:
        def query(self, *args):
            return _Query()

        def close(self):
            pass

    account = {
        "id": "google-1",
        "auth_type": "oauth2_google",
        "oauth_scope": CALDAV_SCOPE,
        "url": (
            "https://apidata.googleusercontent.com/caldav/v2/"
            "person@example.com/user"
        ),
    }
    captured = {}

    async def fake_access_token(owner, account_id, selected):
        captured["token_request"] = (owner, account_id, selected)
        return "write-token", selected

    def fake_google_write(ev, delete, calendar_url, token):
        captured["write"] = (ev, delete, calendar_url, token)
        return {"ok": True, "created": True}

    monkeypatch.setattr(cdb, "SessionLocal", _Session)
    monkeypatch.setattr(sync, "_load_caldav_accounts", lambda owner: [account])
    monkeypatch.setattr(sync, "ensure_google_access_token", fake_access_token)
    monkeypatch.setattr(wb, "_google_writeback_blocking", fake_google_write)
    monkeypatch.setattr(wb, "_persist_writeback_result", lambda *args, **kwargs: None)

    event = _ev(uid="5b1d4e9c-9254-4edc-a9a2-e9136c67f098")
    result = asyncio.run(
        wb.writeback_event("alice", "caldav", "caldav-google", event)
    )

    assert result == {"ok": True, "created": True}
    assert captured["token_request"] == ("alice", "google-1", account)
    assert captured["write"] == (
        event,
        False,
        _GOOGLE_COLLECTION,
        "write-token",
    )


def test_writeback_does_not_fall_back_to_another_stamped_account(monkeypatch):
    import core.database as cdb
    import src.caldav_sync as sync
    import src.caldav_writeback as wb

    calendar_row = types.SimpleNamespace(
        id="caldav-missing-account",
        owner="alice",
        account_id="deleted-account",
        caldav_base_url="https://calendar.example.test/dav/events",
    )

    class _Query:
        def filter(self, *args):
            return self

        def first(self):
            return calendar_row

    class _Session:
        def query(self, *args):
            return _Query()

        def close(self):
            pass

    monkeypatch.setattr(cdb, "SessionLocal", _Session)
    monkeypatch.setattr(
        sync,
        "_load_caldav_accounts",
        lambda owner: [
            {
                "id": "other-account",
                "auth_type": "basic",
                "url": "https://other.example.test/dav",
            }
        ],
    )

    result = asyncio.run(
        wb.writeback_event(
            "alice",
            "caldav",
            "caldav-missing-account",
            _ev(),
        )
    )

    assert result == {"ok": False, "error": "calendar account not found"}


def test_writeback_rejects_missing_owned_calendar_before_account_fallback(
    monkeypatch,
):
    import core.database as cdb
    import src.caldav_sync as sync
    import src.caldav_writeback as wb

    class _Query:
        def filter(self, *args):
            return self

        def first(self):
            return None

    class _Session:
        def query(self, *args):
            return _Query()

        def close(self):
            pass

    monkeypatch.setattr(cdb, "SessionLocal", _Session)
    monkeypatch.setattr(
        sync,
        "_load_caldav_accounts",
        lambda owner: [{"id": "other-account", "auth_type": "basic"}],
    )

    result = asyncio.run(
        wb.writeback_event(
            "alice",
            "caldav",
            "missing-calendar",
            _ev(),
        )
    )

    assert result == {"ok": False, "error": "calendar not found"}
