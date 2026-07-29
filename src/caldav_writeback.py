"""CalDAV write-back: push local create/update/delete out to the remote (#800).

``src/caldav_sync.py`` is a one-way pull (remote → local). So events created,
edited, or deleted in Odysseus on a CalDAV-backed calendar only changed the local
SQLite copy and never reached the server (iCloud/Nextcloud/Radicale/Fastmail) —
they'd silently disappear on the next pull and never show on the user's phone.

This adds the missing write half. The remote calendar URL isn't stored locally
(the local calendar id is a one-way hash of it), so we re-discover the remote
calendar by matching that same hash, then PUT/DELETE the VEVENT by its UID via
the `caldav` lib. Writes are best-effort: the local DB stays the source of truth,
and a remote failure is reported, never fatal to the local operation.

The pure pieces (``build_event_ical``, ``find_remote_calendar``, ``push_event``)
take their inputs by argument so they unit-test against a fake client with no
network.
"""

import asyncio
import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.google_oauth import (
    GOOGLE_CALENDAR_API_BASE,
    google_calendar_events_url,
)

logger = logging.getLogger(__name__)

_GOOGLE_CALDAV_HOST = "apidata.googleusercontent.com"


def _stable_cal_id(remote_url: str, owner: str = "", account_id: str = "") -> str:
    # Reuse the sync module's hashing so owner+account_id scoping stays consistent.
    from src.caldav_sync import _stable_cal_id as _sync_id
    return _sync_id(remote_url, owner=owner, account_id=account_id)


def build_event_ical(ev: dict) -> str:
    """Serialize a local event dict to a VCALENDAR/VEVENT iCalendar string.

    ``ev`` keys: uid, summary, description, location, dtstart (datetime),
    dtend (datetime), all_day (bool), is_utc (bool), rrule (str),
    recurrence_exdates (list[str]).
    Mirrors how the pull path interprets is_utc/all_day so a round-trip is stable.
    """
    from icalendar import Calendar, Event as iEvent
    from icalendar.prop import vRecur

    cal = Calendar()
    cal.add("prodid", "-//Odysseus//CalDAV write-back//EN")
    cal.add("version", "2.0")

    ve = iEvent()
    ve.add("uid", ev["uid"])
    ve.add("summary", ev.get("summary") or "")
    if ev.get("description"):
        ve.add("description", ev["description"])
    if ev.get("location"):
        ve.add("location", ev["location"])

    dtstart = ev["dtstart"]
    dtend = ev["dtend"]
    if ev.get("all_day"):
        ve.add("dtstart", dtstart.date())
        ve.add("dtend", dtend.date())
    elif ev.get("is_utc"):
        # Stored as naive-UTC instants — re-attach UTC so the server gets a Z time.
        ve.add("dtstart", dtstart.replace(tzinfo=timezone.utc))
        ve.add("dtend", dtend.replace(tzinfo=timezone.utc))
    else:
        # Legacy naive-local ("floating") time — emit without a TZ.
        ve.add("dtstart", dtstart)
        ve.add("dtend", dtend)

    if ev.get("rrule"):
        try:
            ve.add("rrule", vRecur.from_ical(ev["rrule"]))
        except Exception:
            logger.debug("CalDAV write-back: skipping unparseable rrule %r", ev.get("rrule"))
    for exdate in ev.get("recurrence_exdates") or []:
        try:
            if ev.get("all_day"):
                ve.add("exdate", datetime.strptime(exdate[:10], "%Y-%m-%d").date())
            else:
                dt = datetime.strptime(exdate[:16], "%Y-%m-%dT%H:%M")
                ve.add("exdate", dt.replace(tzinfo=timezone.utc) if ev.get("is_utc") else dt)
        except Exception:
            logger.debug("CalDAV write-back: skipping unparseable exdate %r", exdate)

    cal.add_component(ve)
    return cal.to_ical().decode("utf-8")


def find_remote_calendar(calendars, local_cal_id: str, owner: str = "", account_id: str = ""):
    """Find the remote calendar whose URL hashes to ``local_cal_id``, or None.

    ``owner`` and ``account_id`` must match what was used when the local calendar
    id was originally computed in ``_sync_blocking`` so the hash round-trips."""
    for cal in calendars:
        try:
            if _stable_cal_id(str(cal.url), owner=owner, account_id=account_id) == local_cal_id:
                return cal
        except Exception:
            continue
    return None


def _resource_href(obj) -> str:
    try:
        return str(getattr(obj, "url", "") or "")
    except Exception:
        return ""


def _resource_etag(obj) -> str:
    try:
        etag = getattr(obj, "etag", None)
        if callable(etag):
            etag = etag()
        return str(etag or "")
    except Exception:
        return ""


def push_event(calendars, local_cal_id: str, ev: dict, *, delete: bool = False,
               owner: str = "", account_id: str = "") -> dict:
    """Create/update (or delete) ``ev`` on the matching remote calendar.

    Returns ``{"ok": bool, ...}``. ``calendars`` is the discovered caldav
    calendar list (injected so this is unit-testable with fakes).
    ``owner`` and ``account_id`` are forwarded to ``find_remote_calendar``
    so the URL hash round-trips correctly (#2765).
    """
    uid = (ev or {}).get("uid") if isinstance(ev, dict) else None
    if not uid:
        return {"ok": False, "error": "event uid is required"}

    remote = find_remote_calendar(calendars, local_cal_id, owner=owner, account_id=account_id)
    if remote is None:
        return {"ok": False, "error": "remote calendar not found"}
    remote_url = str(getattr(remote, "url", "") or "")

    try:
        existing = remote.event_by_uid(uid)
    except Exception:
        existing = None

    if delete:
        if existing is None:
            return {"ok": True, "note": "already absent on remote", "calendar_url": remote_url}
        existing.delete()
        return {
            "ok": True,
            "calendar_url": remote_url,
            "remote_href": _resource_href(existing),
            "remote_etag": _resource_etag(existing),
        }

    ical = build_event_ical(ev)
    if existing is not None:
        existing.data = ical
        existing.save()
        return {
            "ok": True,
            "updated": True,
            "calendar_url": remote_url,
            "remote_href": _resource_href(existing),
            "remote_etag": _resource_etag(existing),
        }
    created = remote.save_event(ical)
    return {
        "ok": True,
        "created": True,
        "calendar_url": remote_url,
        "remote_href": _resource_href(created),
        "remote_etag": _resource_etag(created),
    }


def _discover_calendars(client):
    """Discover the principal's calendars, falling back to the URL itself —
    same strategy as the pull path."""
    from caldav.lib.error import AuthorizationError, NotFoundError
    try:
        return client.principal().calendars()
    except (AuthorizationError, NotFoundError):
        raise
    except Exception:
        try:
            return [client.calendar(url=str(client.url))]
        except Exception:
            return []


def _writeback_blocking(local_cal_id, ev, delete, url, username, password,
                        owner="", account_id="") -> dict:
    from src.caldav_sync import _build_dav_client
    # Redirects disabled here too: the write-back path opens its own DAVClient,
    # so it needs the same SSRF-via-redirect protection as the pull path.
    client = _build_dav_client(url, username, password)
    try:
        calendars = _discover_calendars(client)
        if not calendars:
            return {"ok": False, "error": "no remote calendars discovered"}
        return push_event(calendars, local_cal_id, ev, delete=delete,
                          owner=owner, account_id=account_id)
    finally:
        client.close()


def _google_calendar_id_from_url(raw_url: str) -> str:
    """Extract a Calendar API id from ``/caldav/v2/<id>/events`` safely."""
    parsed = urlparse(raw_url if isinstance(raw_url, str) else "")
    if (
        parsed.scheme != "https"
        or parsed.hostname != _GOOGLE_CALDAV_HOST
        or parsed.port is not None
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Google calendar collection URL is invalid")
    segments = parsed.path.rstrip("/").split("/")
    if len(segments) != 5 or segments[:3] != ["", "caldav", "v2"] or segments[4] != "events":
        raise ValueError("Google calendar collection URL is invalid")
    calendar_id = unquote(segments[3])
    if not calendar_id or any(ch in calendar_id for ch in "/?%"):
        raise ValueError("Google calendar collection URL is invalid")
    return calendar_id


def _google_event_id_from_payload(calendar_id: str, ev: dict) -> str:
    """Resolve the Google event id from a pinned API href or imported UID."""
    href = str((ev or {}).get("remote_href") or "")
    if href:
        parsed = urlparse(href)
        segments = parsed.path.rstrip("/").split("/")
        if (
            parsed.scheme == "https"
            and parsed.hostname == urlparse(GOOGLE_CALENDAR_API_BASE).hostname
            and parsed.port is None
            and not parsed.username
            and not parsed.password
            and not parsed.params
            and not parsed.query
            and not parsed.fragment
            and len(segments) == 7
            and segments[:4] == ["", "calendar", "v3", "calendars"]
            and segments[5] == "events"
            and unquote(segments[4]) == calendar_id
        ):
            event_id = unquote(segments[6])
            if event_id and "/" not in event_id:
                return event_id

    uid = str((ev or {}).get("uid") or "")
    match = re.fullmatch(r"google-([0-9a-f]{16})-(.+)", uid)
    expected_hash = hashlib.sha256(calendar_id.encode("utf-8")).hexdigest()[:16]
    if (
        match
        and match.group(1) == expected_hash
        and "/" not in match.group(2)
    ):
        return match.group(2)
    return ""


def _host_timezone_name() -> str:
    """Resolve the Mac's IANA time zone without adding a runtime dependency."""
    for location in (Path("/etc/localtime"), Path("/var/db/timezone/localtime")):
        try:
            resolved = str(location.resolve())
        except OSError:
            continue
        marker = "/zoneinfo/"
        if marker in resolved:
            candidate = resolved.split(marker, 1)[1]
            try:
                ZoneInfo(candidate)
            except (ValueError, ZoneInfoNotFoundError):
                continue
            return candidate
    key = getattr(datetime.now().astimezone().tzinfo, "key", "")
    if key:
        try:
            ZoneInfo(str(key))
            return str(key)
        except (ValueError, ZoneInfoNotFoundError):
            pass
    return ""


def _validated_timezone_name(value: object) -> str:
    candidate = str(value or "").strip() or _host_timezone_name()
    if not candidate:
        raise ValueError(
            "event timezone is required before writing a local time to Google"
        )
    try:
        ZoneInfo(candidate)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        raise ValueError("event timezone is invalid") from exc
    return candidate


def _google_datetime_payload(
    value: datetime, *, all_day: bool, is_utc: bool, timezone_name: str = ""
) -> dict:
    if not isinstance(value, datetime):
        raise ValueError("event start and end must be datetimes")
    if all_day:
        return {"date": value.date().isoformat()}
    if is_utc:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)
        return {"dateTime": value.isoformat().replace("+00:00", "Z")}
    if value.tzinfo is None:
        # Keep the wall-clock value and bind it to an IANA zone. A fixed offset
        # makes recurring events drift when daylight-saving time changes.
        zone = _validated_timezone_name(timezone_name)
        return {"dateTime": value.isoformat(), "timeZone": zone}
    payload = {"dateTime": value.isoformat()}
    zone = getattr(value.tzinfo, "key", "") or timezone_name
    if zone:
        payload["timeZone"] = _validated_timezone_name(zone)
    return payload


def _google_recurrence_payload(
    ev: dict, *, recurrence_timezone: str
) -> list[str]:
    rrule = str(ev.get("rrule") or "").strip()
    if not rrule:
        return []
    rule_lines = [line.strip() for line in rrule.splitlines() if line.strip()]
    rule_line = next(
        (line for line in rule_lines if line.upper().startswith("RRULE:")),
        rule_lines[0] if rule_lines else "",
    )
    if rule_line.upper().startswith("RRULE:"):
        rule_line = rule_line.split(":", 1)[1]
    if not rule_line:
        return []
    lines = [f"RRULE:{rule_line}"]
    for raw_exdate in ev.get("recurrence_exdates") or []:
        try:
            raw = str(raw_exdate).strip()
            if ev.get("all_day"):
                parsed_date = datetime.fromisoformat(raw[:10]).date()
                lines.append(
                    f"EXDATE;VALUE=DATE:{parsed_date.strftime('%Y%m%d')}"
                )
                continue
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if ev.get("is_utc") or parsed.tzinfo is not None:
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                parsed = parsed.astimezone(timezone.utc)
                lines.append(f"EXDATE:{parsed.strftime('%Y%m%dT%H%M%SZ')}")
            else:
                zone = _validated_timezone_name(recurrence_timezone)
                lines.append(
                    f"EXDATE;TZID={zone}:{parsed.strftime('%Y%m%dT%H%M%S')}"
                )
        except (TypeError, ValueError):
            logger.debug(
                "Google Calendar write-back: skipping unparseable exdate %r",
                raw_exdate,
            )
    return lines


def _google_event_payload(
    ev: dict, *, include_recurrence: bool = True
) -> dict:
    """Translate Odysseus event fields to a Google Calendar Event resource."""
    all_day = bool(ev.get("all_day"))
    is_utc = bool(ev.get("is_utc"))
    dtstart = ev.get("dtstart")
    if not isinstance(dtstart, datetime):
        raise ValueError("event start is required")
    dtend = ev.get("dtend")
    if all_day and (
        not isinstance(dtend, datetime) or dtend.date() <= dtstart.date()
    ):
        dtend = dtstart + timedelta(days=1)
    elif dtend is None:
        dtend = dtstart
    if not isinstance(dtend, datetime):
        raise ValueError("event end must be a datetime")
    timezone_name = str(ev.get("timezone") or "")
    start_payload = _google_datetime_payload(
        dtstart,
        all_day=all_day,
        is_utc=is_utc,
        timezone_name=timezone_name,
    )
    end_payload = _google_datetime_payload(
        dtend,
        all_day=all_day,
        is_utc=is_utc,
        timezone_name=timezone_name,
    )
    has_rule = bool(str(ev.get("rrule") or "").strip())
    recurrence_timezone = ""
    if has_rule and not all_day:
        recurrence_timezone = (
            "UTC"
            if is_utc
            else str(start_payload.get("timeZone") or "")
            or _validated_timezone_name(timezone_name)
        )
    recurrence = (
        _google_recurrence_payload(
            ev, recurrence_timezone=recurrence_timezone
        )
        if include_recurrence
        else []
    )
    body = {
        "summary": str(ev.get("summary") or ""),
        "description": str(ev.get("description") or ""),
        "location": str(ev.get("location") or ""),
        "start": start_payload,
        "end": end_payload,
    }
    if include_recurrence:
        # PATCH uses merge semantics, so an explicit empty list is required to
        # turn a formerly recurring Google event into a single event.
        body["recurrence"] = recurrence
    if recurrence and not all_day:
        body["start"]["timeZone"] = recurrence_timezone
        body["end"]["timeZone"] = recurrence_timezone
    try:
        local_uid = str(uuid.UUID(str(ev.get("uid") or "")))
    except (ValueError, TypeError):
        local_uid = ""
    if local_uid:
        body["extendedProperties"] = {"private": {"odysseus_uid": local_uid}}
    return body


def _google_writeback_blocking(
    ev: dict,
    delete: bool,
    calendar_url: str,
    access_token: str,
) -> dict:
    """Create, patch, or delete one Google event through Calendar API."""
    import httpx

    calendar_id = _google_calendar_id_from_url(calendar_url)
    collection_url = google_calendar_events_url(calendar_id)
    event_id = _google_event_id_from_payload(calendar_id, ev)
    event_url = google_calendar_events_url(calendar_id, event_id) if event_id else ""
    base_headers = {"Authorization": f"Bearer {access_token}"}
    headers = dict(base_headers)
    if event_id and ev.get("remote_etag"):
        headers["If-Match"] = str(ev["remote_etag"])

    with httpx.Client(timeout=30.0, follow_redirects=False, trust_env=False) as client:
        if delete:
            if not event_url:
                return {
                    "ok": False,
                    "error": "Google Calendar event id is unavailable for delete",
                }
            response = client.delete(event_url, headers=headers)
            if response.status_code in {404, 410}:
                return {"ok": True, "note": "already absent on remote"}
            if response.status_code == 412:
                return {
                    "ok": False,
                    "conflict": True,
                    "error": "Google Calendar event changed before delete",
                }
            response.raise_for_status()
            return {"ok": True, "calendar_url": calendar_url}

        payload_event = dict(ev)
        include_recurrence = True
        needs_remote_metadata = bool(payload_event.get("rrule")) or bool(
            re.fullmatch(
                r".+_\d{8}(?:T\d{6}Z?)?",
                str(event_id or ""),
            )
        )
        if event_url and needs_remote_metadata:
            current = client.get(event_url, headers=base_headers)
            if current.status_code not in {404, 410}:
                current.raise_for_status()
                current_event = current.json()
                include_recurrence = not bool(
                    current_event.get("recurringEventId")
                )
                source_zone = str(
                    (current_event.get("start") or {}).get("timeZone") or ""
                )
                if (
                    include_recurrence
                    and payload_event.get("rrule")
                    and payload_event.get("is_utc")
                    and source_zone
                ):
                    try:
                        zone = ZoneInfo(source_zone)
                    except ZoneInfoNotFoundError as exc:
                        raise ValueError(
                            "Google Calendar event has an unknown timezone"
                        ) from exc
                    for field in ("dtstart", "dtend"):
                        value = payload_event.get(field)
                        if isinstance(value, datetime):
                            payload_event[field] = value.replace(
                                tzinfo=timezone.utc
                            ).astimezone(zone)
                    payload_event["is_utc"] = False
                    payload_event["timezone"] = source_zone
        body = _google_event_payload(
            payload_event,
            include_recurrence=include_recurrence,
        )
        if event_url:
            response = client.patch(event_url, headers=headers, json=body)
            updated = True
            if response.status_code in {404, 410}:
                response = client.post(
                    collection_url, headers=base_headers, json=body
                )
                updated = False
            elif response.status_code == 412:
                return {
                    "ok": False,
                    "conflict": True,
                    "error": "Google Calendar event changed before update",
                }
        else:
            response = client.post(
                collection_url, headers=base_headers, json=body
            )
            updated = False
        response.raise_for_status()
        remote = response.json()
        remote_id = str(remote.get("id") or event_id)
        if not remote_id:
            raise RuntimeError("Google Calendar did not return an event id")
        remote_href = f"{collection_url}/{quote(remote_id, safe='')}"
        return {
            "ok": True,
            "updated": updated,
            "created": not updated,
            "calendar_url": calendar_url,
            "remote_href": remote_href,
            "remote_etag": str(remote.get("etag") or ""),
        }


def _persist_writeback_result(owner: str, calendar_id: str, uid: str, result: dict, *, delete: bool) -> None:
    from core.database import CalendarCal, CalendarDeletedEvent, CalendarEvent, SessionLocal

    if not uid or not isinstance(result, dict):
        return

    db = SessionLocal()
    try:
        calendar = db.query(CalendarCal).filter(
            CalendarCal.id == calendar_id,
            CalendarCal.owner == owner,
        ).first()
        if calendar and result.get("calendar_url"):
            calendar.caldav_base_url = result.get("calendar_url")

        if delete:
            tombstone = db.query(CalendarDeletedEvent).filter(
                CalendarDeletedEvent.uid == uid,
                CalendarDeletedEvent.owner == owner,
            ).first()
            if result.get("ok"):
                if tombstone:
                    db.delete(tombstone)
            elif result.get("conflict"):
                # Preserve the concurrently changed Google event. Removing the
                # tombstone lets the next pull re-import it instead of retrying
                # the same stale destructive delete forever.
                if tombstone:
                    db.delete(tombstone)
            elif tombstone:
                tombstone.last_error = str(result.get("error") or result)[:500]
            db.commit()
            return

        event = (
            db.query(CalendarEvent)
            .join(CalendarCal)
            .filter(CalendarEvent.uid == uid, CalendarCal.owner == owner)
            .first()
        )
        if event:
            if result.get("ok"):
                if result.get("remote_href"):
                    event.remote_href = result.get("remote_href")
                if result.get("remote_etag"):
                    event.remote_etag = result.get("remote_etag")
                event.caldav_sync_pending = None
            elif result.get("conflict"):
                # Google wins a detected concurrent edit. The next pull can
                # now refresh both the row and its ETag instead of endlessly
                # replaying the stale If-Match value.
                event.remote_etag = None
                event.caldav_sync_pending = None
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("CalDAV write-back metadata persistence failed")
    finally:
        db.close()


async def writeback_event(owner: str, calendar_source: str, calendar_id: str,
                          ev: dict, *, delete: bool = False) -> dict:
    """Best-effort push of a local change to the remote CalDAV server.

    No-ops (``{"skipped": ...}``) when the calendar isn't CalDAV-backed or no
    credentials are configured. Never raises — a remote failure is logged and
    returned, the local DB remaining the source of truth.
    """
    if calendar_source != "caldav":
        return {"skipped": "not a caldav calendar"}
    try:
        from src.caldav_sync import _load_caldav_accounts
        from core.database import CalendarCal, SessionLocal

        accounts = _load_caldav_accounts(owner)
        if not accounts:
            return {"skipped": "caldav not configured"}

        # Resolve the owned local calendar first; its account_id prevents a
        # write from being routed through another user's or account's token.
        cal_row = None
        db = SessionLocal()
        try:
            cal_row = db.query(CalendarCal).filter(
                CalendarCal.id == calendar_id,
                CalendarCal.owner == owner,
            ).first()
            cal_account_id = cal_row.account_id if cal_row else None
            calendar_url = cal_row.caldav_base_url if cal_row else None
        finally:
            db.close()

        if cal_row is None:
            return {"ok": False, "error": "calendar not found"}

        acc = None
        if cal_account_id:
            acc = next((a for a in accounts if a.get("id") == cal_account_id), None)
            if acc is None:
                return {"ok": False, "error": "calendar account not found"}
        else:
            # Fall back only for legacy rows that predate account_id stamping.
            acc = accounts[0]

        auth_type = acc.get("auth_type") or "basic"
        acc_id = acc.get("id") or ""
        if auth_type == "oauth2_google":
            if not calendar_url:
                return {
                    "ok": False,
                    "error": "calendar has no remote URL",
                }
            from src.caldav_sync import (
                ensure_google_access_token,
                validate_google_caldav_url,
            )

            try:
                validate_google_caldav_url((acc.get("url") or "").strip())
                # The collection URL came from Google's authenticated calendar
                # list and is independently pinned/validated by the writer.
                _google_calendar_id_from_url(calendar_url or "")
                access_token, _updated = await ensure_google_access_token(
                    owner, acc_id, acc
                )
            except (ValueError, RuntimeError) as exc:
                return {"ok": False, "error": str(exc)[:200]}
            result = await asyncio.to_thread(
                _google_writeback_blocking,
                ev,
                delete,
                calendar_url,
                access_token,
            )
            _persist_writeback_result(
                owner,
                calendar_id,
                (ev or {}).get("uid", ""),
                result,
                delete=delete,
            )
            if not result.get("ok"):
                logger.warning(
                    "Google Calendar write-back did not apply: %s",
                    result.get("error") or result,
                )
            return result

        if auth_type != "basic":
            return {"ok": False, "error": "unsupported CalDAV auth type"}

        from src.secret_storage import decrypt
        url = (acc.get("url") or "").strip()
        user = (acc.get("username") or "").strip()
        pw = decrypt(acc.get("password") or "")
        if not (url and user and pw):
            return {"skipped": "caldav account credentials incomplete"}
        from src.caldav_sync import validate_caldav_url
        try:
            url = validate_caldav_url(url)
        except ValueError as e:
            logger.warning("CalDAV write-back URL rejected: %s", e)
            return {"ok": False, "error": str(e)[:200]}
        result = await asyncio.to_thread(
            _writeback_blocking, calendar_id, ev, delete, url, user, pw, owner, acc_id
        )
        _persist_writeback_result(owner, calendar_id, (ev or {}).get("uid", ""), result, delete=delete)
        if not result.get("ok"):
            logger.warning("CalDAV write-back did not apply: %s", result.get("error") or result)
        return result
    except Exception as e:
        logger.exception("CalDAV write-back raised")
        result = {"ok": False, "error": str(e)[:200]}
        _persist_writeback_result(owner, calendar_id, (ev or {}).get("uid", ""), result, delete=delete)
        return result
