"""Timestamp normalization — every artifact time as ISO 8601 UTC.

Forensic rules enforced here:
- full source precision is kept (EZ Tools emit 7 fractional digits; they are
  not truncated to Python's microseconds);
- a missing or unparseable time stays ``None`` with a reason — it is never
  replaced by "now" or any other invented value;
- ambiguous day/month formats (``01/02/2024``) are refused, not guessed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

# Values tools emit for "no timestamp"
_EMPTY = {"", "n/a", "na", "null", "none", "0", "-", "1601-01-01 00:00:00", "0001-01-01 00:00:00"}

_ISO_LIKE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:[.,](?P<frac>\d+))?"
    r"\s*(?P<tz>Z|UTC|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)
_SLASH_YMD = re.compile(r"^(\d{4})/(\d{2})/(\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?$")

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
# Zero values emitted as dates by parsers (FILETIME 0, Unix epoch 0)
_ZERO_TIMES = (datetime(1601, 1, 1, tzinfo=UTC), datetime(1970, 1, 1, tzinfo=UTC))
_MIN_YEAR, _MAX_YEAR = 1980, 2100  # plausibility window for epoch-style numbers (1970 ≈ a zeroed field)


def _format(dt: datetime, frac: str | None) -> str:
    base = dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{frac}Z" if frac else f"{base}Z"


def _from_number(value: float) -> tuple[str | None, str | None]:
    """Epoch seconds / milliseconds or Windows FILETIME."""
    if value <= 0:
        return None, None
    candidates = []
    if value > 1e17:  # FILETIME: 100 ns ticks since 1601
        candidates.append(_FILETIME_EPOCH + timedelta(microseconds=value / 10))
    elif value > 1e11:  # epoch milliseconds
        candidates.append(datetime.fromtimestamp(value / 1000, tz=UTC))
    else:  # epoch seconds
        candidates.append(datetime.fromtimestamp(value, tz=UTC))
    dt = candidates[0]
    if not (_MIN_YEAR <= dt.year <= _MAX_YEAR):
        return None, f"implausible numeric timestamp: {value!r}"
    frac = f"{dt.microsecond:06d}".rstrip("0") or None
    return _format(dt.replace(microsecond=0), frac), None


def to_utc_iso(value) -> tuple[str | None, str | None]:
    """Normalize a timestamp to ISO 8601 UTC (``YYYY-MM-DDTHH:MM:SS[.f]Z``).

    Returns:
        ``(iso, None)`` on success, ``(None, None)`` for an empty value,
        ``(None, reason)`` when the value cannot be interpreted safely.
    """
    if value is None:
        return None, None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)  # tools emit UTC unless stated
        frac = f"{value.microsecond:06d}".rstrip("0") or None
        return _format(value.replace(microsecond=0), frac), None
    if isinstance(value, bool):
        return None, f"not a timestamp: {value!r}"
    if isinstance(value, int | float):
        return _from_number(float(value))

    text = str(value).strip()
    if text.lower() in _EMPTY:
        return None, None

    match = _ISO_LIKE.match(text)
    if match:
        tz_text = (match.group("tz") or "").upper()
        try:
            dt = datetime.strptime(  # noqa: DTZ007
                f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None, f"invalid date/time: {text!r}"
        if tz_text in ("", "Z", "UTC"):
            dt = dt.replace(tzinfo=UTC)  # no offset: tools emit UTC
        else:
            sign = 1 if tz_text[0] == "+" else -1
            digits = tz_text[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            dt = dt.replace(tzinfo=timezone(sign * offset))
        if dt.year < 1601:
            return None, f"out of range: {text!r}"
        if dt.astimezone(UTC) in _ZERO_TIMES and not match.group("frac"):
            return None, None  # zeroed FILETIME / epoch field: "no timestamp"
        frac = (match.group("frac") or "").rstrip("0") or None
        return _format(dt, frac), None

    match = _SLASH_YMD.match(text)
    if match:
        return to_utc_iso(f"{match.group(1)}-{match.group(2)}-{match.group(3)} "
                          f"{match.group(4)}{'.' + match.group(5) if match.group(5) else ''}")

    if re.fullmatch(r"\d{10}(\d{3})?(\d{5})?", text):
        return _from_number(float(text))

    return None, f"unrecognized timestamp format: {text!r}"


def parse_timestamp(value) -> str | None:
    """Normalize a timestamp for an artifact field.

    Unlike the top-level ``timestamp`` (validated by the pipeline), secondary
    fields keep the raw value when it cannot be parsed — it is evidence.
    """
    iso, error = to_utc_iso(value)
    if iso:
        return iso
    if error and value is not None:
        return str(value).strip()
    return None
