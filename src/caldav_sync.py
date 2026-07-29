"""CalDAV → local SQLite sync.

The Settings UI lets users save CalDAV credentials, but the original
sync path was removed when calendar storage was migrated to SQLite.
This module re-wires that gap as a one-way pull (remote → local),
called on calendar open and from a periodic scheduler loop.

Design notes:
- We use the `caldav` lib so PROPFIND discovery + REPORT XML work
  across Radicale / Nextcloud / Apple / Fastmail without us
  reinventing the protocol. It's pure Python.
- The lib is synchronous; we run it in a threadpool via
  `asyncio.to_thread` so the FastAPI event loop stays free.
- Each remote calendar maps to one local `CalendarCal` row with
  `source="caldav"` and `id` = a stable hash of the remote URL so
  re-syncs idempotently target the same row.
- Events upsert by VEVENT UID (kept as the local `uid`). Local
  CalDAV-sourced events not seen in the latest pull are deleted so
  remote deletions propagate.
- Datetimes are converted to UTC and the row is flagged `is_utc=True`
  so the serializer adds the Z suffix and the frontend renders in the
  user's local TZ correctly.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import socket
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from urllib.parse import quote, unquote, urlparse, urlunparse
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)

# Pull window: 90 days back, 1 year forward. Keeps the REPORT cheap and
# matches what the calendar UI typically renders. Far-future recurring
# events still come through via RRULE expansion on the frontend.
_LOOKBACK_DAYS = 90
_LOOKAHEAD_DAYS = 365
_BLOCKED_HOSTS = {
    "localhost",
    "localhost.",
    "ip6-localhost",
    "metadata.google.internal",
}
_GOOGLE_CALDAV_HOST = "apidata.googleusercontent.com"
_GOOGLE_CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3"
_GOOGLE_PATH_SAFE = "@!$&'()*+,;=._~-"
# A host-pinned response is still untrusted input.  Keep XML parsing bounded
# so a broken or compromised response cannot consume unbounded memory.
_GOOGLE_REPORT_MAX_BYTES = 16 * 1024 * 1024
_GOOGLE_API_MAX_CALENDARS = 250
_GOOGLE_API_MAX_EVENTS = 10_000


@dataclass(frozen=True)
class _GoogleCalendarFeed:
    """One Google Calendar API collection prepared for the common importer."""

    url: str
    name: str
    color: str
    icals: tuple[str, ...]


def _private_caldav_allowed() -> bool:
    return os.environ.get("ODYSSEUS_ALLOW_PRIVATE_CALDAV", "0").lower() in {"1", "true", "yes"}


def _validate_caldav_address(addr: ipaddress._BaseAddress) -> None:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        raise ValueError("CalDAV URL host is not allowed")
    if addr.is_private and not _private_caldav_allowed():
        raise ValueError("Private CalDAV IPs require ODYSSEUS_ALLOW_PRIVATE_CALDAV=1")


def _validate_caldav_ip(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return
    _validate_caldav_address(ip)


def _resolve_caldav_host_ips(host: str) -> list[ipaddress._BaseAddress]:
    addrs: list[ipaddress._BaseAddress] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        try:
            addrs.append(ipaddress.ip_address(sockaddr[0].split("%", 1)[0]))
        except ValueError:
            continue
    return addrs


def _validate_caldav_hostname(host: str) -> None:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return
    except ValueError:
        pass
    try:
        addrs = _resolve_caldav_host_ips(host)
    except OSError:
        raise ValueError("CalDAV URL host does not resolve")
    if not addrs:
        raise ValueError("CalDAV URL host does not resolve")
    for addr in addrs:
        _validate_caldav_address(addr)


def validate_caldav_url(raw_url: str) -> str:
    """Validate and normalize a user-provided CalDAV URL before server-side use."""
    url = (raw_url if isinstance(raw_url, str) else "").strip()
    if not url:
        raise ValueError("CalDAV URL is required")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("CalDAV URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("CalDAV URL must include a host")
    if parsed.username or parsed.password:
        raise ValueError("Put CalDAV credentials in the username/password fields, not the URL")
    if parsed.fragment:
        raise ValueError("CalDAV URL fragments are not allowed")
    try:
        parsed.port
    except ValueError:
        raise ValueError("CalDAV URL has an invalid port")
    host = (parsed.hostname or "").lower()
    if host in _BLOCKED_HOSTS or host.endswith(".localhost"):
        raise ValueError("CalDAV URL host is not allowed")
    _validate_caldav_ip(host)
    _validate_caldav_hostname(host)
    return urlunparse(parsed._replace(fragment="")).rstrip("/")


def _event_etag(obj) -> str:
    """Best-effort ETag extraction from python-caldav resources."""
    try:
        etag = getattr(obj, "etag", None)
        if callable(etag):
            etag = etag()
        return str(etag or "")
    except Exception:
        return ""


def _stable_cal_id(remote_url: str, owner: str = "", account_id: str = "") -> str:
    """Deterministic local id for a remote CalDAV calendar, scoped to owner
    and account so two users — or one user with two accounts — pointing at
    the same server URL get distinct local rows (avoids PK collision, #2765).
    The owner and account_id default to "" for the legacy/URL-only path so
    existing callers without those arguments keep working."""
    key = f"{owner}\n{account_id}\n{remote_url}"
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
    return f"caldav-{h}"


def _to_utc_naive(dt):
    """CalDAV datetimes can be tz-aware (with a TZID) or naive. The DB
    column is naive but we set is_utc=True so the serializer adds Z.
    All-day events stay as date and get widened to datetime here."""
    if isinstance(dt, datetime):
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None), False
        return dt, False  # naive → treat as local
    # date-only (all-day)
    return datetime(dt.year, dt.month, dt.day), True


def _find_existing_event(db, pending, uid_val, calendar_id):
    """Find the event to update for THIS calendar.

    CalendarEvent.uid is the global primary key, so an unscoped lookup by uid
    returns whatever row holds that VEVENT uid — including another owner's.
    The old code then reassigned that row's calendar_id, moving (stealing)
    another user's event into the syncing calendar whenever the two share a
    uid (shared/subscribed/public calendars, or two accounts on one server).
    Scope the lookup to the calendar being synced; a genuine cross-user uid
    collision then fails the PK insert inside the per-calendar try/except
    instead of hijacking the row. (import_ics was already fixed this way.)
    """
    from core.database import CalendarEvent
    return pending.get(uid_val) or db.query(CalendarEvent).filter(
        CalendarEvent.uid == uid_val,
        CalendarEvent.calendar_id == calendar_id,
    ).first()


def _google_caldav_events_url(url: str) -> str | None:
    """Map a Google CalDAV *principal* URL to its event-collection URL.

    Google serves the principal at ``…/user`` but events live under ``…/events``
    — the ``/user`` resource holds no VEVENTs. The `caldav` library's
    principal→home-set discovery does not reliably enumerate calendars from
    Google's ``/user`` endpoint, so the sync falls into the "treat the URL as a
    single calendar" fallback below. Pointed at ``/user`` that fallback issues
    every calendar-query REPORT against the principal, which returns a clean but
    empty 200 for all date ranges — the calendar shows no events even though
    auth succeeded (issue #2507).

    Both Google CalDAV endpoint forms are handled, since some accounts only
    authenticate against one of them:
      - newer:  ``https://apidata.googleusercontent.com/caldav/v2/<id>/user``
      - legacy: ``https://www.google.com/calendar/dav/<id>/user``

    Returns the events URL for a recognised Google principal URL, else None so
    the caller keeps the original URL unchanged.
    """
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    if not path.endswith("/user"):
        return None
    is_google = (
        host == _GOOGLE_CALDAV_HOST                                    # newer /caldav/v2 form
        or (host in ("www.google.com", "google.com") and "/calendar/dav/" in path)  # legacy form
    )
    if not is_google:
        return None
    new_path = path[: -len("/user")] + "/events"
    return urlunparse(parts._replace(path=new_path))


def _canonical_google_path(path: str) -> tuple[list[str], str]:
    """Decode path segments for comparison, then quote them for transport."""
    raw_path = path.rstrip("/")
    raw_segments = raw_path.split("/")
    decoded = [unquote(segment) for segment in raw_segments]
    canonical = [quote(segment, safe=_GOOGLE_PATH_SAFE) for segment in decoded]
    return decoded, "/".join(canonical)


def _validate_google_path_segments(decoded: list[str], *, principal: bool) -> str:
    if len(decoded) < 5 or decoded[0] != "" or decoded[1:3] != ["caldav", "v2"]:
        raise ValueError("Google CalDAV URL must be /caldav/v2/<account>/user")
    account = decoded[3]
    if not account or account in {".", ".."} or any(ch in account for ch in "/?#%"):
        raise ValueError("Google CalDAV URL has an invalid account path")
    if principal and (len(decoded) != 5 or decoded[4] != "user"):
        raise ValueError("Google CalDAV URL must be /caldav/v2/<account>/user")
    for segment in decoded[1:]:
        if segment in {".", ".."} or any(ch in segment for ch in "/?#%"):
            raise ValueError("Google CalDAV target path is not allowed")
    return account


def validate_google_caldav_url(raw_url: str) -> str:
    """Validate a Google OAuth CalDAV principal URL.

    OAuth credentials are only valid for Google's HTTPS CalDAV endpoint.  The
    configured URL is intentionally narrower than the generic CalDAV URL
    validator: it must be ``/caldav/v2/<account>/user`` on the exact Google
    host.  This keeps a bearer token from being sent to an arbitrary server.
    """
    url = (raw_url if isinstance(raw_url, str) else "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != _GOOGLE_CALDAV_HOST:
        raise ValueError("Google CalDAV URL must use https://apidata.googleusercontent.com")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Google CalDAV URL contains unsupported credentials or query data")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Google CalDAV URL has an invalid port") from exc
    if port is not None:
        raise ValueError("Google CalDAV URL must not specify a port")
    decoded, canonical_path = _canonical_google_path(parsed.path)
    account = _validate_google_path_segments(decoded, principal=True)
    return urlunparse(parsed._replace(path=canonical_path, params="")).rstrip("/")


def _google_account_prefix(configured_url: str) -> str:
    """Return the normalized collection prefix for a configured account."""
    principal = validate_google_caldav_url(configured_url)
    decoded, _canonical = _canonical_google_path(urlparse(principal).path)
    return decoded[3]


def validate_google_caldav_target(configured_url: str, target_url: str) -> str:
    """Validate a discovered Google collection before attaching a bearer token."""
    account = _google_account_prefix(configured_url)
    target = (target_url if isinstance(target_url, str) else "").strip()
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.hostname != _GOOGLE_CALDAV_HOST:
        raise ValueError("Google CalDAV target host is not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Google CalDAV target has an invalid port") from exc
    if port is not None or parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Google CalDAV target URL is not allowed")
    decoded, canonical_path = _canonical_google_path(parsed.path)
    target_account = _validate_google_path_segments(decoded, principal=False)
    if target_account != account:
        raise ValueError("Google CalDAV target is outside the configured account")
    if any(not segment for segment in decoded[1:]):
        raise ValueError("Google CalDAV target path is not allowed")
    return urlunparse(parsed._replace(path=canonical_path, params="")).rstrip("/")


def _canonical_google_report_target(raw_url: str) -> str:
    target = (raw_url if isinstance(raw_url, str) else "").strip()
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.hostname != _GOOGLE_CALDAV_HOST:
        raise ValueError("Google CalDAV REPORT target is not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Google CalDAV REPORT target has an invalid port") from exc
    if port is not None or parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Google CalDAV REPORT target is not allowed")
    decoded, canonical_path = _canonical_google_path(parsed.path)
    _validate_google_path_segments(decoded, principal=False)
    if len(decoded) < 5 or any(not segment for segment in decoded[1:]):
        raise ValueError("Google CalDAV REPORT target path is not allowed")
    return urlunparse(parsed._replace(path=canonical_path, params="")).rstrip("/")


def _open_url_as_calendar(client, url: str):
    """Open ``url`` as a single calendar collection.

    Used when principal discovery yields no calendars. Google's principal URL
    is not an event collection, so map it to the events URL first
    (see ``_google_caldav_events_url``); other servers' URLs are used as-is.
    """
    target = _google_caldav_events_url(url) or url
    return client.calendar(url=target)


def _google_fetch_icals(access_token: str, cal_url: str, start: datetime, end: datetime) -> list[str]:
    """Fetch events from a Google CalDAV calendar via raw REPORT.

    The caldav library's date_search issues a REPORT to get the multistatus of
    events, but then re-GETs each event URL individually. Google returns 404 for
    certain recurring-event instance URLs (e.g. _R20230424 occurrence IDs) which
    the library converts to NotFoundError and our code misidentifies as "empty
    calendar." This function does the REPORT directly and extracts inline
    <caldav:calendar-data> from the multistatus, skipping the per-event GETs
    entirely.
    """
    import httpx
    # stdlib ElementTree does not resolve external entities or fetch network
    # resources.  Keep the parser local and dependency-free for untrusted DAV
    # responses.
    import xml.etree.ElementTree as _etree

    target = _canonical_google_report_target(cal_url)

    def _report_time(value: datetime) -> str:
        # _sync_blocking supplies naive UTC datetimes via datetime.utcnow().
        # Treat any naive caller value as UTC; normalize aware values first.
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.strftime("%Y%m%dT%H%M%SZ")

    start_s = _report_time(start)
    end_s = _report_time(end)
    report_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:">'
        "<D:prop><C:calendar-data/></D:prop>"
        "<C:filter><C:comp-filter name=\"VCALENDAR\">"
        '<C:comp-filter name="VEVENT">'
        f'<C:time-range start="{start_s}" end="{end_s}"/>'
        "</C:comp-filter></C:comp-filter></C:filter>"
        "</C:calendar-query>"
    ).encode()

    with httpx.Client(timeout=30.0, follow_redirects=False, trust_env=False) as cx:
        with cx.stream(
            "REPORT", target,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Depth": "1",
                "Content-Type": "application/xml",
            },
            content=report_body,
        ) as r:
            if r.status_code not in (200, 207):
                raise RuntimeError(f"REPORT returned HTTP {r.status_code}")
            response_chunks = []
            response_size = 0
            for chunk in r.iter_bytes():
                response_size += len(chunk)
                if response_size > _GOOGLE_REPORT_MAX_BYTES:
                    raise RuntimeError("REPORT response exceeded the size limit")
                response_chunks.append(chunk)
    response_content = b"".join(response_chunks)

    ns = {"D": "DAV:", "C": "urn:ietf:params:xml:ns:caldav"}
    try:
        tree = _etree.fromstring(response_content)
    except Exception as e:
        raise Exception(f"REPORT response parse error: {e}") from e

    icals: list[str] = []
    for response in tree.findall(".//D:response", ns):
        # A response can contain multiple propstat entries.  Do not assume
        # the first one is the successful representation.
        saw_calendar_data = False
        saw_successful_calendar_data = False
        for propstat in response.findall("D:propstat", ns):
            status_el = propstat.find("D:status", ns)
            status_parts = (status_el.text or "").split() if status_el is not None else []
            cal_data = propstat.find("D:prop/C:calendar-data", ns)
            if cal_data is None:
                continue
            saw_calendar_data = True
            if len(status_parts) < 2 or status_parts[1] != "200":
                continue
            if not cal_data.text or not cal_data.text.strip():
                raise RuntimeError("REPORT calendar-data property was empty")
            icals.append(cal_data.text)
            saw_successful_calendar_data = True
        if not saw_calendar_data:
            # The REPORT requested only calendar-data.  A response that omits
            # that representation is incomplete, not an empty event set.
            raise RuntimeError("REPORT calendar-data property missing")
        if not saw_successful_calendar_data:
            raise RuntimeError("REPORT calendar-data property failed")
    return icals


def _google_api_timestamp(value: datetime) -> str:
    """Serialize a sync boundary as RFC 3339 UTC for Google Calendar API."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _google_event_datetime(value: dict):
    """Convert a Google event ``start``/``end`` object to iCalendar input."""
    if value.get("date"):
        return date.fromisoformat(value["date"])
    raw = value.get("dateTime")
    if not raw:
        raise ValueError("Google event has no date or dateTime")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None and value.get("timeZone"):
        parsed = parsed.replace(tzinfo=ZoneInfo(str(value["timeZone"])))
    return parsed


def _google_event_to_ical(calendar_id: str, item: dict) -> str:
    """Convert one Calendar API event into a small VCALENDAR document."""
    from icalendar import Calendar as iCal, Event as iEvent, vRecur

    event_id = str(item.get("id") or "")
    if not event_id:
        raise ValueError("Google event has no id")

    calendar_hash = hashlib.sha256(calendar_id.encode("utf-8")).hexdigest()[:16]
    event = iEvent()
    event.add("uid", f"google-{calendar_hash}-{event_id}")
    event.add("dtstart", _google_event_datetime(item.get("start") or {}))
    if item.get("end"):
        event.add("dtend", _google_event_datetime(item["end"]))
    for field in ("summary", "description", "location"):
        value = item.get(field)
        if value:
            event.add(field, str(value))
    for recurrence in item.get("recurrence") or []:
        if isinstance(recurrence, str) and recurrence.upper().startswith("RRULE:"):
            event.add("rrule", vRecur.from_ical(recurrence.split(":", 1)[1]))
            break

    calendar = iCal()
    calendar.add("prodid", "-//Odysseus//Google Calendar read-only sync//EN")
    calendar.add("version", "2.0")
    calendar.add_component(event)
    return calendar.to_ical().decode("utf-8")


def _google_fetch_calendar_feeds(
    access_token: str, start: datetime, end: datetime
) -> list[_GoogleCalendarFeed]:
    """Fetch subscribed calendars and events through Google's read-only API.

    Google currently accepts the ``calendar.readonly`` token for Calendar API
    requests but can reject CalDAV ``calendar-query`` REPORT requests with 403.
    Use the REST API for the Google-OAuth pull path so the integration remains
    least-privileged. Generic username/password accounts still use CalDAV.
    """
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    calendars: list[dict] = []

    with httpx.Client(timeout=30.0, follow_redirects=False, trust_env=False) as cx:
        page_token = None
        seen_page_tokens: set[str] = set()
        while True:
            params = {"maxResults": 250}
            if page_token:
                params["pageToken"] = page_token
            response = cx.get(
                f"{_GOOGLE_CALENDAR_API_BASE}/users/me/calendarList",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            payload = response.json()
            calendars.extend(payload.get("items") or [])
            if len(calendars) > _GOOGLE_API_MAX_CALENDARS:
                raise RuntimeError("Google calendar list exceeded the safety limit")
            page_token = payload.get("nextPageToken")
            if not page_token:
                break
            if page_token in seen_page_tokens:
                raise RuntimeError("Google calendar list pagination repeated")
            seen_page_tokens.add(page_token)

        feeds: list[_GoogleCalendarFeed] = []
        total_events = 0
        for remote in calendars:
            calendar_id = str(remote.get("id") or "")
            if not calendar_id:
                continue
            event_items: list[dict] = []
            page_token = None
            seen_page_tokens = set()
            while True:
                params = {
                    "timeMin": _google_api_timestamp(start),
                    "timeMax": _google_api_timestamp(end),
                    # Expand recurrences server-side so moved/cancelled instances
                    # are represented exactly within our bounded sync window.
                    "singleEvents": "true",
                    "showDeleted": "false",
                    "maxResults": 2500,
                }
                if page_token:
                    params["pageToken"] = page_token
                response = cx.get(
                    f"{_GOOGLE_CALENDAR_API_BASE}/calendars/"
                    f"{quote(calendar_id, safe='')}/events",
                    headers=headers,
                    params=params,
                )
                response.raise_for_status()
                payload = response.json()
                event_items.extend(payload.get("items") or [])
                total_events += len(payload.get("items") or [])
                if total_events > _GOOGLE_API_MAX_EVENTS:
                    raise RuntimeError("Google events exceeded the safety limit")
                page_token = payload.get("nextPageToken")
                if not page_token:
                    break
                if page_token in seen_page_tokens:
                    raise RuntimeError("Google events pagination repeated")
                seen_page_tokens.add(page_token)

            icals = []
            for item in event_items:
                if item.get("status") == "cancelled" or not item.get("start"):
                    continue
                try:
                    icals.append(_google_event_to_ical(calendar_id, item))
                except (TypeError, ValueError) as exc:
                    logger.warning(
                        "Skipping malformed Google event in calendar %s: %s",
                        calendar_id,
                        exc,
                    )

            encoded_id = quote(calendar_id, safe=_GOOGLE_PATH_SAFE)
            feeds.append(
                _GoogleCalendarFeed(
                    url=(
                        f"https://{_GOOGLE_CALDAV_HOST}/caldav/v2/"
                        f"{encoded_id}/events"
                    ),
                    name=str(remote.get("summaryOverride") or remote.get("summary") or "Google Calendar"),
                    color=str(remote.get("backgroundColor") or "#5b8abf"),
                    icals=tuple(icals),
                )
            )
    return feeds


def _build_dav_client(url: str, username: str = "", password: str = "", access_token: str = ""):
    """Construct a CalDAV client with automatic redirects disabled.

    ``validate_caldav_url`` resolves and vets the *initial* host, but caldav's
    underlying HTTP session follows 3xx redirects by default. So a URL that
    passes validation can still be redirected — at request time — to
    loopback / link-local / private space, re-opening the SSRF the host check
    closes. Pin the session to zero redirects: any 3xx then raises instead of
    silently following an attacker-chosen ``Location``. This mirrors the
    test-connection path in ``routes/calendar_routes.py``, which already sets
    ``follow_redirects=False``.

    DAVClient exposes no per-request redirect flag, so we set it on the session
    after construction (the session is created in ``__init__``).

    When ``access_token`` is provided (Google OAuth) the client sends a Bearer
    token instead of Basic credentials.
    """
    import caldav

    kwargs = (
        {"headers": {"Authorization": f"Bearer {access_token}"}}
        if access_token
        else {"username": username, "password": password}
    )
    client = caldav.DAVClient(url=url, **kwargs)
    client.session.max_redirects = 0
    return client


def _should_prune_window(seen_uids: set, parse_failed: bool) -> bool:
    """Whether the post-sync prune of vanished CalDAV events is safe to run.

    The prune deletes local ``origin=="caldav"`` rows in the window whose UID the
    server did not just return. Any parse failure (total or partial) makes
    ``seen_uids`` an incomplete view of the server, so pruning against it can
    delete events that still exist upstream but could not be read: a total
    failure wipes the whole window, a partial failure deletes just the
    unreadable ones. Only prune on a clean read. An empty ``seen_uids`` after a
    clean read is a genuinely empty window, which is safe to prune.
    """
    return not parse_failed


def _sync_blocking(owner: str, url: str, username: str = "", password: str = "", account_id: str = "", access_token: str = "") -> dict:
    """The actual sync — synchronous, intended to run in a threadpool.
    Returns counts: {calendars, events, deleted, errors}."""
    # Lazy imports so a missing `caldav` dep doesn't break app startup —
    # the integrations form still works, sync just no-ops with an error.
    from caldav.lib.error import AuthorizationError, NotFoundError
    from core.database import CalendarCal, CalendarEvent, SessionLocal
    from routes.calendar_routes import _ensure_positive_duration

    result = {"calendars": 0, "events": 0, "deleted": 0, "errors": []}

    if access_token:
        # OAuth accounts are constrained to Google's exact principal contract
        # before a bearer token is ever used by the DAV client.
        try:
            url = validate_google_caldav_url(url)
        except ValueError as e:
            result["errors"].append(str(e))
            return result

    start = datetime.utcnow() - timedelta(days=_LOOKBACK_DAYS)
    end = datetime.utcnow() + timedelta(days=_LOOKAHEAD_DAYS)

    client = None
    try:
        if access_token:
            try:
                calendars = _google_fetch_calendar_feeds(access_token, start, end)
            except Exception as e:
                result["errors"].append(f"Google Calendar API failed ({e})")
                return result
        else:
            client = _build_dav_client(url, username, password)
            # Discovery: try principal → calendars first; if the server doesn't
            # support discovery (or the URL points directly at a calendar), fall
            # back to treating the URL as a single calendar.
            calendars = []
            try:
                principal = client.principal()
                calendars = principal.calendars()
            except (AuthorizationError, NotFoundError) as e:
                result["errors"].append(f"Discovery failed: {e}")
                return result
            except Exception as e:
                logger.info(f"CalDAV principal discovery failed, trying URL as calendar: {e}")
                try:
                    calendars = [_open_url_as_calendar(client, url)]
                except Exception as e2:
                    result["errors"].append(f"Could not open URL as calendar: {e2}")
                    return result

            if not calendars:
                try:
                    calendars = [_open_url_as_calendar(client, url)]
                except Exception as e:
                    result["errors"].append(f"No calendars and URL fallback failed: {e}")
                    return result

        db = SessionLocal()        # if this raises, outer finally still calls client.close()
        try:
            for remote_cal in calendars:
                try:
                    remote_url = str(remote_cal.url)
                    cal_id = _stable_cal_id(remote_url, owner=owner, account_id=account_id)
                    display_name = (remote_cal.name or "").strip() or "CalDAV"
                    calendar_color = getattr(remote_cal, "color", "") or "#5b8abf"

                    local_cal = db.query(CalendarCal).filter(
                        CalendarCal.id == cal_id,
                        CalendarCal.owner == owner,
                    ).first()
                    if not local_cal:
                        local_cal = CalendarCal(
                            id=cal_id,
                            owner=owner,
                            name=display_name,
                            color=calendar_color,
                            source="caldav",
                            account_id=account_id or None,
                            caldav_base_url=remote_url,
                        )
                        db.add(local_cal)
                        db.commit()
                    else:
                        # Refresh display name and stamp CalDAV metadata if missing.
                        changed = False
                        if local_cal.name != display_name:
                            local_cal.name = display_name
                            changed = True
                        if account_id and not local_cal.account_id:
                            local_cal.account_id = account_id
                            changed = True
                        if local_cal.caldav_base_url != remote_url:
                            local_cal.caldav_base_url = remote_url
                            changed = True
                        if local_cal.color != calendar_color:
                            local_cal.color = calendar_color
                            changed = True
                        if changed:
                            db.commit()
                    result["calendars"] += 1

                    # Fetch events in window. `date_search` returns CalendarObject
                    # resources; each may contain one VEVENT (most servers) or
                    # several (rare).
                    from icalendar import Calendar as iCal

                    seen_uids = set()
                    # Track events added to the session but not yet committed so
                    # duplicate UIDs within the same batch are updated, not re-inserted
                    # (which would violates the UNIQUE constraint on commit).
                    pending: dict = {}
                    parse_failed = False
                    prune_blocked = False
                    if access_token:
                        ical_records = [
                            (ical_text, None) for ical_text in remote_cal.icals
                        ]
                    else:
                        try:
                            objs = remote_cal.date_search(start=start, end=end, expand=False)
                            ical_records = []
                            for obj in objs:
                                try:
                                    ical_records.append((obj.data, obj))
                                except Exception as e:
                                    result["errors"].append(
                                        f"{display_name}: parse failed ({e})"
                                    )
                                    parse_failed = True
                        except NotFoundError as e:
                            # caldav uses this exception for both an empty window
                            # and ambiguous REPORT failures, so never prune here.
                            if "No events found" in str(e):
                                ical_records = []
                                prune_blocked = True
                            else:
                                result["errors"].append(
                                    f"{display_name}: date_search failed ({e})"
                                )
                                continue
                        except Exception as e:
                            result["errors"].append(
                                f"{display_name}: date_search failed ({e})"
                            )
                            continue

                    for ical_text, resource in ical_records:
                        try:
                            ical = iCal.from_ical(ical_text)
                        except Exception as e:
                            result["errors"].append(f"{display_name}: parse failed ({e})")
                            parse_failed = True
                            continue

                        for comp in ical.walk():
                            if comp.name != "VEVENT":
                                continue
                            uid_val = str(comp.get("uid", "")) or str(uuid.uuid4())
                            seen_uids.add(uid_val)

                            dtstart_p = comp.get("dtstart")
                            if not dtstart_p:
                                continue
                            start_dt, all_day = _to_utc_naive(dtstart_p.dt)

                            dtend_p = comp.get("dtend")
                            if dtend_p:
                                end_dt, _ = _to_utc_naive(dtend_p.dt)
                            elif all_day:
                                end_dt = start_dt + timedelta(days=1)
                            else:
                                end_dt = start_dt + timedelta(hours=1)
                            # A synced event with DTEND <= DTSTART (e.g. a single-day
                            # all-day event whose source wrote DTEND equal to DTSTART)
                            # would be stored zero-duration and silently dropped by the
                            # list_events overlap filter. Clamp to a positive span.
                            end_dt = _ensure_positive_duration(start_dt, end_dt, all_day)

                            # is_utc reflects whether the source carried a TZ
                            # we converted from. All-day = no TZ semantics.
                            row_is_utc = (
                                not all_day
                                and isinstance(dtstart_p.dt, datetime)
                                and dtstart_p.dt.tzinfo is not None
                            )

                            summary = str(comp.get("summary", ""))
                            description = str(comp.get("description", ""))
                            location = str(comp.get("location", ""))
                            rrule = (
                                comp.get("rrule").to_ical().decode()
                                if comp.get("rrule")
                                else ""
                            )

                            resource_href = (
                                str(getattr(resource, "url", "") or "")
                                if resource is not None
                                else remote_url
                            ) or None
                            resource_etag = (
                                _event_etag(resource) if resource is not None else ""
                            ) or None

                            existing = _find_existing_event(db, pending, uid_val, local_cal.id)
                            if existing:
                                if existing.caldav_sync_pending in {"create", "update"}:
                                    result["events"] += 1
                                    continue
                                existing.calendar_id = local_cal.id
                                existing.summary = summary
                                existing.description = description
                                existing.location = location
                                existing.dtstart = start_dt
                                existing.dtend = end_dt
                                existing.all_day = all_day
                                existing.is_utc = row_is_utc
                                existing.rrule = rrule
                                existing.origin = "caldav"
                                existing.remote_href = resource_href
                                existing.remote_etag = resource_etag
                                existing.caldav_sync_pending = None
                            else:
                                new_ev = CalendarEvent(
                                    uid=uid_val,
                                    calendar_id=local_cal.id,
                                    summary=summary,
                                    description=description,
                                    location=location,
                                    dtstart=start_dt,
                                    dtend=end_dt,
                                    all_day=all_day,
                                    is_utc=row_is_utc,
                                    rrule=rrule,
                                    origin="caldav",
                                    remote_href=resource_href,
                                    remote_etag=resource_etag,
                                )
                                db.add(new_ev)
                                pending[uid_val] = new_ev
                            result["events"] += 1
                    db.commit()

                    # Prune locally-cached CalDAV events that vanished
                    # upstream (only within our sync window — events outside
                    # the window aren't in `objs`, so we'd false-delete them).
                    # Only rows we previously pulled from the server (origin=="caldav")
                    # are prunable; locally-created events (agent / email triage / a
                    # UI event whose write-back failed) carry origin NULL and must
                    # never be deleted just because the server didn't return them.
                    # Skip the prune on any parse failure: seen_uids is then an
                    # incomplete view of the server, so pruning against it would
                    # delete events that still exist upstream but could not be read
                    # (the empty-seen_uids case wipes the whole window; a partial
                    # failure deletes just the unreadable rows).
                    if _should_prune_window(seen_uids, parse_failed or prune_blocked):
                        stale = db.query(CalendarEvent).filter(
                            CalendarEvent.calendar_id == local_cal.id,
                            CalendarEvent.origin == "caldav",
                            CalendarEvent.dtstart >= start,
                            CalendarEvent.dtstart <= end,
                            CalendarEvent.remote_href.isnot(None),
                            CalendarEvent.caldav_sync_pending.is_(None),
                            ~CalendarEvent.uid.in_(seen_uids) if seen_uids else CalendarEvent.uid.isnot(None),
                        ).all()
                        for ev in stale:
                            db.delete(ev)
                        result["deleted"] += len(stale)
                        db.commit()
                except Exception as e:
                    logger.exception("CalDAV sync failed for one calendar")
                    result["errors"].append(str(e)[:200])
                    db.rollback()
        finally:
            db.close()             # NOT client.close() here anymore

        return result
    finally:
        if client is not None:
            client.close()


def _event_payload(ev) -> dict:
    return {
        "uid": ev.uid,
        "summary": ev.summary,
        "description": ev.description,
        "location": ev.location,
        "dtstart": ev.dtstart,
        "dtend": ev.dtend,
        "all_day": ev.all_day,
        "is_utc": ev.is_utc,
        "rrule": ev.rrule or "",
        "recurrence_exdates": json.loads(ev.recurrence_exdates or "[]") if getattr(ev, "recurrence_exdates", "") else [],
    }


def _load_event_for_writeback(owner: str, uid: str) -> tuple[str, str, dict] | None:
    from core.database import CalendarCal, CalendarEvent, SessionLocal

    db = SessionLocal()
    try:
        ev = (
            db.query(CalendarEvent)
            .join(CalendarCal)
            .filter(CalendarEvent.uid == uid, CalendarCal.owner == owner)
            .first()
        )
        if not ev or not ev.calendar or ev.calendar.source != "caldav":
            return None
        return ev.calendar.source, ev.calendar.id, _event_payload(ev)
    finally:
        db.close()


def _load_delete_for_writeback(owner: str, uid: str) -> tuple[str, str, dict] | None:
    from core.database import CalendarCal, CalendarDeletedEvent, CalendarEvent, SessionLocal

    db = SessionLocal()
    try:
        tombstone = db.query(CalendarDeletedEvent).filter(
            CalendarDeletedEvent.uid == uid,
            CalendarDeletedEvent.owner == owner,
        ).first()
        if tombstone:
            return "caldav", tombstone.calendar_id, {"uid": uid}

        ev = (
            db.query(CalendarEvent)
            .join(CalendarCal)
            .filter(CalendarEvent.uid == uid, CalendarCal.owner == owner)
            .first()
        )
        if not ev or not ev.calendar or ev.calendar.source != "caldav":
            return None
        return ev.calendar.source, ev.calendar.id, {"uid": uid}
    finally:
        db.close()


def _pending_writeback_uids(owner: str) -> tuple[list[str], list[str]]:
    from core.database import CalendarCal, CalendarDeletedEvent, CalendarEvent, SessionLocal

    db = SessionLocal()
    try:
        rows = (
            db.query(CalendarEvent.uid)
            .join(CalendarCal)
            .filter(
                CalendarCal.owner == owner,
                CalendarCal.source == "caldav",
                CalendarEvent.status != "cancelled",
                (
                    (CalendarEvent.caldav_sync_pending.isnot(None))
                    | (CalendarEvent.remote_href.is_(None))
                ),
            )
            .all()
        )
        delete_rows = (
            db.query(CalendarDeletedEvent.uid)
            .filter(CalendarDeletedEvent.owner == owner)
            .all()
        )
        return [row[0] for row in rows], [row[0] for row in delete_rows]
    finally:
        db.close()


def _load_caldav_accounts(owner: str) -> list:
    """Return the list of CalDAV accounts for *owner*, auto-migrating the legacy
    single-account ``caldav`` key to the new ``caldav_accounts`` list on first call.

    The save step is best-effort: if ``_save_for_user`` is unavailable (e.g. in a
    test with a minimal prefs mock) the migrated accounts are still returned; the
    next real call will just re-run the cheap migration again.
    """
    import uuid as _uuid
    from routes.prefs_routes import _load_for_user

    prefs = _load_for_user(owner) or {}
    if "caldav_accounts" in prefs:
        return list(prefs["caldav_accounts"] or [])
    # Migrate legacy single-account config to the list format.
    legacy = prefs.get("caldav", {}) or {}
    if legacy.get("url"):
        accounts = [{
            "id": str(_uuid.uuid4()),
            "label": "CalDAV",
            "url": legacy["url"],
            "username": legacy.get("username", ""),
            "password": legacy.get("password", ""),
        }]
        prefs["caldav_accounts"] = accounts
        prefs.pop("caldav", None)
        try:
            from routes.prefs_routes import _save_for_user
            _save_for_user(owner, prefs)
        except (ImportError, AttributeError):
            pass  # best-effort; next call re-migrates from the still-present legacy key
        return accounts
    return []


def save_caldav_accounts(owner: str, accounts: list) -> None:
    """Save account settings without replacing the current preferences object."""
    from routes.prefs_routes import _load_for_user, _save_for_user

    prefs = _load_for_user(owner) or {}
    prefs["caldav_accounts"] = accounts
    prefs.pop("caldav", None)
    _save_for_user(owner, prefs)


async def ensure_google_access_token(
    owner: str, account_id: str, account: dict
) -> tuple[str, dict]:
    """Return a usable Google access token and persist refreshes safely.

    A successful refresh updates only token fields on the latest account record
    loaded by id.  This avoids overwriting a concurrent label/URL edit with a
    stale list held by a long-running sync or request.
    """
    import time as _time
    from src.secret_storage import decrypt, encrypt

    current = dict(account)
    expected_auth_type = current.get("auth_type") or "basic"
    if expected_auth_type != "oauth2_google":
        raise RuntimeError("Google account changed while refreshing")
    try:
        access_token = decrypt(current.get("oauth_access_token") or "")
    except Exception as exc:
        logger.warning(
            "Could not decrypt Google access token for account %s: %s",
            account_id,
            type(exc).__name__,
        )
        raise ValueError("Stored Google credentials are invalid") from exc
    expires_at = current.get("oauth_expires_at") or 0
    try:
        still_valid = bool(access_token) and _time.time() < float(expires_at)
    except (TypeError, ValueError):
        still_valid = False
    if still_valid:
        return access_token, current

    raw_client_id = current.get("oauth_client_id") or ""
    client_id = raw_client_id.strip() if isinstance(raw_client_id, str) else ""
    try:
        client_secret = decrypt(current.get("oauth_client_secret") or "")
        refresh_token = decrypt(current.get("oauth_refresh_token") or "")
    except Exception as exc:
        logger.warning(
            "Could not decrypt Google credentials for account %s: %s",
            account_id,
            type(exc).__name__,
        )
        raise ValueError("Stored Google credentials are invalid") from exc
    expected_secret_stored = current.get("oauth_client_secret") or ""
    expected_refresh_stored = current.get("oauth_refresh_token") or ""
    if not (client_id and client_secret and refresh_token):
        raise ValueError("Google account is not connected")

    from src.google_oauth import refresh_access_token

    def _reload_matching_account():
        try:
            latest_accounts = _load_caldav_accounts(owner)
        except Exception as exc:
            logger.exception(
                "Failed to reload Google account %s before persisting a refreshed token",
                account_id,
            )
            raise RuntimeError("Google account could not be reloaded while refreshing") from exc

        latest_idx = next(
            (i for i, item in enumerate(latest_accounts) if item.get("id") == account_id),
            None,
        )
        if latest_idx is None:
            raise RuntimeError("Google account changed while refreshing")
        latest = dict(latest_accounts[latest_idx])
        latest_client_id = latest.get("oauth_client_id") or ""
        latest_client_id = (
            latest_client_id.strip() if isinstance(latest_client_id, str) else ""
        )
        if (
            latest.get("auth_type") != expected_auth_type
            or latest_client_id != client_id
            or (latest.get("oauth_client_secret") or "") != expected_secret_stored
            or (latest.get("oauth_refresh_token") or "") != expected_refresh_stored
        ):
            logger.warning("Google account %s credentials changed during refresh", account_id)
            raise RuntimeError("Google account changed while refreshing")
        return latest_accounts, latest_idx, latest

    def _refresh_error_code(exc: Exception) -> str | None:
        code = getattr(exc, "error_code", None) or getattr(exc, "oauth_error", None)
        if code:
            return str(code)
        response = getattr(exc, "response", None)
        if response is not None:
            try:
                code = response.json().get("error")
            except Exception:
                code = None
        return str(code) if code else None

    try:
        refreshed = await refresh_access_token(client_id, client_secret, refresh_token)
    except Exception as exc:
        if _refresh_error_code(exc) in {"invalid_grant", "invalid_client"}:
            # Re-check the encrypted credential revision before clearing the
            # unusable tokens.  A concurrent edit must never be erased.
            latest_accounts, latest_idx, latest = _reload_matching_account()
            latest["oauth_access_token"] = ""
            latest["oauth_refresh_token"] = ""
            latest["oauth_expires_at"] = 0
            latest_accounts[latest_idx] = latest
            try:
                save_caldav_accounts(owner, latest_accounts)
            except Exception as save_exc:
                logger.exception(
                    "Failed to clear invalid Google credentials for account %s",
                    account_id,
                )
                raise RuntimeError("Google credentials could not be cleared") from save_exc
            raise ValueError("Google credentials are invalid; reconnect required") from exc
        logger.warning("Google token refresh failed for account %s: %s", account_id, type(exc).__name__)
        raise RuntimeError("Google token refresh failed") from exc

    access_token = str(refreshed.get("access_token") or "")
    if not access_token:
        raise RuntimeError("Google token refresh returned no access token")
    current["oauth_access_token"] = encrypt(access_token)
    current["oauth_expires_at"] = refreshed.get("expires_at", 0)
    if refreshed.get("refresh_token"):
        current["oauth_refresh_token"] = encrypt(str(refreshed["refresh_token"]))

    # Reload current account state before writing, preserving unrelated edits.
    latest_accounts, latest_idx, latest = _reload_matching_account()

    latest["oauth_access_token"] = current["oauth_access_token"]
    latest["oauth_expires_at"] = current["oauth_expires_at"]
    if refreshed.get("refresh_token"):
        latest["oauth_refresh_token"] = current["oauth_refresh_token"]
    latest_accounts[latest_idx] = latest
    try:
        save_caldav_accounts(owner, latest_accounts)
        current = latest
    except Exception as exc:
        logger.exception("Failed to persist refreshed Google token for account %s", account_id)
        raise RuntimeError("Failed to persist refreshed Google token") from exc

    return access_token, current


async def sync_caldav(owner: str) -> dict:
    """Pull CalDAV state into local DB for `owner` across all configured accounts.
    Returns aggregated counts + per-account errors."""
    from src.secret_storage import decrypt

    accounts = _load_caldav_accounts(owner)
    if not accounts:
        return {
            "calendars": 0, "events": 0, "deleted": 0,
            "errors": ["CalDAV is not configured"],
        }

    totals: dict = {"calendars": 0, "events": 0, "deleted": 0, "errors": []}
    for acc in accounts:
        url = (acc.get("url") or "").strip()
        account_id = acc.get("id") or ""
        label = acc.get("label") or url or account_id
        auth_type = acc.get("auth_type") or "basic"

        if auth_type == "oauth2_google":
            if not url:
                totals["errors"].append(f"{label}: missing URL or access token")
                continue
            try:
                validated = validate_google_caldav_url(url)
            except ValueError as e:
                totals["errors"].append(f"{label}: {e}")
                continue
            try:
                access_token, _updated = await ensure_google_access_token(owner, account_id, acc)
            except ValueError as exc:
                if "invalid" in str(exc).lower():
                    totals["errors"].append(
                        f"{label}: stored Google credentials are invalid — reconnect from Settings"
                    )
                    continue
                totals["errors"].append(
                    f"{label}: not connected to Google — go to Settings → Integrations to reconnect"
                )
                continue
            except RuntimeError:
                totals["errors"].append(f"{label}: token refresh failed")
                continue
            except Exception as exc:
                logger.warning(
                    "Could not read Google credentials for account %s: %s",
                    account_id,
                    type(exc).__name__,
                )
                totals["errors"].append(
                    f"{label}: stored Google credentials are invalid — reconnect from Settings"
                )
                continue

            if not access_token:
                totals["errors"].append(f"{label}: missing URL or access token")
                continue

            try:
                result = await asyncio.to_thread(_sync_blocking, owner, validated, "", "", account_id, access_token)
            except ValueError as e:
                result = {"calendars": 0, "events": 0, "deleted": 0, "errors": [str(e)]}
            except Exception as e:
                logger.exception("CalDAV sync raised for account %s", label)
                result = {"calendars": 0, "events": 0, "deleted": 0, "errors": [str(e)[:200]]}

        elif auth_type == "basic":
            user = (acc.get("username") or "").strip()
            pw = acc.get("password") or ""
            try:
                pw = decrypt(pw)
            except Exception:
                pass
            if not (url and user and pw):
                totals["errors"].append(f"{label}: missing URL, username, or password")
                continue
            try:
                validated = validate_caldav_url(url)
                result = await asyncio.to_thread(_sync_blocking, owner, validated, user, pw, account_id)
            except ValueError as e:
                result = {"calendars": 0, "events": 0, "deleted": 0, "errors": [str(e)]}
            except Exception as e:
                logger.exception("CalDAV sync raised for account %s", label)
                result = {"calendars": 0, "events": 0, "deleted": 0, "errors": [str(e)[:200]]}

        else:
            totals["errors"].append(f"{label}: unsupported CalDAV auth type")
            continue

        totals["calendars"] += result.get("calendars", 0)
        totals["events"] += result.get("events", 0)
        totals["deleted"] += result.get("deleted", 0)
        for err in result.get("errors", []):
            totals["errors"].append(f"{label}: {err}")

    return totals


async def push_event_create(owner: str, uid: str) -> dict:
    loaded = _load_event_for_writeback(owner, uid)
    if not loaded:
        return {"ok": True, "skipped": True}
    source, calendar_id, payload = loaded
    from src.caldav_writeback import writeback_event
    return await writeback_event(owner, source, calendar_id, payload)


async def push_event_update(owner: str, uid: str) -> dict:
    return await push_event_create(owner, uid)


async def push_event_delete(owner: str, uid: str) -> dict:
    loaded = _load_delete_for_writeback(owner, uid)
    if not loaded:
        return {"ok": True, "skipped": True}
    source, calendar_id, payload = loaded
    from src.caldav_writeback import writeback_event
    return await writeback_event(owner, source, calendar_id, payload, delete=True)


async def push_pending_events(owner: str) -> dict:
    result = {"events": 0, "errors": []}
    uids, delete_uids = _pending_writeback_uids(owner)
    for event_uid in uids:
        try:
            out = await push_event_update(owner, event_uid)
            if out.get("ok"):
                result["events"] += 1
            elif not out.get("skipped"):
                result["errors"].append(f"{event_uid}: {str(out.get('error') or out)[:160]}")
        except Exception as e:
            logger.warning("CalDAV pending push failed for uid=%s: %s", event_uid, e)
            result["errors"].append(f"{event_uid}: {str(e)[:160]}")
    for event_uid in delete_uids:
        try:
            out = await push_event_delete(owner, event_uid)
            if out.get("ok"):
                result["events"] += 1
            elif not out.get("skipped"):
                result["errors"].append(f"{event_uid}: {str(out.get('error') or out)[:160]}")
        except Exception as e:
            logger.warning("CalDAV pending delete failed for uid=%s: %s", event_uid, e)
            result["errors"].append(f"{event_uid}: {str(e)[:160]}")
    return result


async def sync_caldav_direction(owner: str, direction: str = "pull") -> dict:
    direction = (direction or "pull").strip().lower()
    if direction == "pull":
        return await sync_caldav(owner)
    if direction == "push":
        return await push_pending_events(owner)
    if direction == "both":
        pushed = await push_pending_events(owner)
        pulled = await sync_caldav(owner)
        return {"push": pushed, "pull": pulled}
    return {
        "calendars": 0,
        "events": 0,
        "deleted": 0,
        "errors": [f"Unsupported CalDAV sync direction: {direction}"],
    }
