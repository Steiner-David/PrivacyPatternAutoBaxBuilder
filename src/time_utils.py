import logging
import os
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


PROJECT_TIMEZONE_NAME = os.getenv("AUTOBAX_TIMEZONE") or os.getenv("TZ") or "Europe/Vienna"
os.environ.setdefault("TZ", PROJECT_TIMEZONE_NAME)
if hasattr(time, "tzset"):
    time.tzset()


def _last_sunday(year: int, month: int) -> datetime:
    day = datetime(year, month + 1, 1, tzinfo=timezone.utc) - timedelta(days=1)
    return day - timedelta(days=(day.weekday() + 1) % 7)


def _europe_vienna_fallback(utc_dt: datetime) -> datetime:
    start = _last_sunday(utc_dt.year, 3).replace(hour=1, minute=0, second=0)
    end = _last_sunday(utc_dt.year, 10).replace(hour=1, minute=0, second=0)
    offset_hours = 2 if start <= utc_dt < end else 1
    return utc_dt.astimezone(
        timezone(timedelta(hours=offset_hours), PROJECT_TIMEZONE_NAME)
    )


def project_datetime(timestamp: float | None = None) -> datetime:
    utc_dt = (
        datetime.now(timezone.utc)
        if timestamp is None
        else datetime.fromtimestamp(timestamp, timezone.utc)
    )
    try:
        return utc_dt.astimezone(ZoneInfo(PROJECT_TIMEZONE_NAME))
    except ZoneInfoNotFoundError:
        if PROJECT_TIMEZONE_NAME == "Europe/Vienna":
            return _europe_vienna_fallback(utc_dt)
        return utc_dt.astimezone()


def format_project_timestamp(
    timestamp: float | None = None,
    *,
    include_milliseconds: bool = False,
    msecs: float | None = None,
) -> str:
    dt = project_datetime(timestamp)
    formatted = dt.strftime("%Y-%m-%d %H:%M:%S")
    if include_milliseconds:
        millis = int(msecs if msecs is not None else dt.microsecond / 1000)
        formatted += f",{millis:03d}"
    return formatted


class ProjectFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        if datefmt:
            return project_datetime(record.created).strftime(datefmt)
        return format_project_timestamp(
            record.created, include_milliseconds=True, msecs=record.msecs
        )
