"""Cron schedules for scheduled scans: `cron = "0 2 * * sat Asia/Ho_Chi_Minh"` (G23).

Five fields — minute, hour, day of month, month, day of week — as in crontab(5):

    *        every value            1-5      a range             */15    every 15th
    1,15,30  a list                 1-10/3   a range, stepped    mon-fri, jan  names

with the usual rule for the two "day" fields: when both are restricted, a day matches if
*either* does (`0 2 1 * mon`: the 1st of the month and every Monday). Day of week 0 and 7
are Sunday. An optional sixth word is the time zone: an IANA name (`Europe/Berlin`, daylight
saving time included), `UTC`, or a fixed offset (`+07:00`); without it, UTC.

A schedule must leave at least `MIN_GAP` between two scans (like `every`): `* * * * *` is
refused. Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MIN_GAP = timedelta(minutes=5)

_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
_DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
_FIELDS = (
    # name, lowest, highest, names (index + offset = value)
    ("minute", 0, 59, None),
    ("hour", 0, 23, None),
    ("day of month", 1, 31, None),
    ("month", 1, 12, (_MONTHS, 1)),
    ("day of week", 0, 7, (_DAYS, 0)),
)
_OFFSET = re.compile(r"([+-])(\d{2}):?(\d{2})")


class CronError(ValueError):
    """The schedule cannot be used; the message says why, for the person who wrote it."""


@dataclass(frozen=True)
class Cron:
    text: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday ... 6 = Saturday
    any_day: bool  # day of month was "*"
    any_weekday: bool  # day of week was "*"
    zone: tzinfo

    @classmethod
    def parse(cls, text: str) -> Cron:
        words = text.split()
        if len(words) not in (5, 6):
            raise CronError(
                f"cron {text!r}: five fields (minute hour day month weekday) and an optional "
                'time zone, e.g. "0 2 * * sat Asia/Ho_Chi_Minh"'
            )
        sets = [_field(word, *spec) for word, spec in zip(words[:5], _FIELDS, strict=True)]
        weekdays = frozenset(d % 7 for d in sets[4])  # 7 is Sunday too
        cron = cls(
            text=" ".join(words),
            minutes=sets[0],
            hours=sets[1],
            days=sets[2],
            months=sets[3],
            weekdays=weekdays,
            any_day=words[2] == "*",
            any_weekday=words[4] == "*",
            zone=_zone(words[5]) if len(words) == 6 else UTC,
        )
        cron._check_gap()
        return cron

    def _day_matches(self, day: datetime) -> bool:
        in_month = day.day in self.days
        in_week = (day.isoweekday() % 7) in self.weekdays
        if self.any_day and self.any_weekday:
            return True
        if self.any_day:
            return in_week
        if self.any_weekday:
            return in_month
        return in_month or in_week  # both restricted: either one (crontab(5))

    def next_after(self, moment: datetime) -> datetime:
        """The first time this schedule fires strictly after `moment` (aware), in UTC."""
        local = moment.astimezone(self.zone).replace(tzinfo=None, second=0, microsecond=0)
        at = local + timedelta(minutes=1)
        # "0 0 29 2 *" fires every leap year, and 2096 -> 2104 is 8 years apart.
        limit = local + timedelta(days=366 * 9)
        while at <= limit:
            if at.month not in self.months:
                at = _first_of_next_month(at)
            elif not self._day_matches(at):
                at = datetime(at.year, at.month, at.day) + timedelta(days=1)
            elif at.hour not in self.hours:
                at = at.replace(minute=0) + timedelta(hours=1)
            elif at.minute not in self.minutes:
                at += timedelta(minutes=1)
            else:
                fired = at.replace(tzinfo=self.zone).astimezone(UTC)
                if fired > moment:  # a local time repeated when the clocks go back
                    return fired
                at += timedelta(minutes=1)
        raise CronError(f"cron {self.text!r} never fires (e.g. the 31st of a 30-day month)")

    def latest_at_or_before(self, moment: datetime) -> datetime | None:
        """The last time it fired at or before `moment` (None: not in the last 9 years)."""
        # Step forward through the firings of a window that ends at `moment`, widened
        # until it holds one: a day of "*/15" is 96 steps, not a year's 35,000.
        for days in (1, 7, 32, 366, 366 * 9):
            latest = None
            at = self.next_after(moment - timedelta(days=days))
            while at <= moment:
                latest = at
                at = self.next_after(at)
            if latest is not None:
                return latest
        return None

    def _check_gap(self) -> None:
        """At least MIN_GAP between firings. Every day that fires does so at the same
        times, so a day of firings and the step into the next day show it: 500 firings
        (more than a day's at 5-minute gaps) or a year, whichever comes first."""
        start = at = self.next_after(datetime(2026, 1, 1, tzinfo=UTC))
        for _ in range(500):
            if at - start > timedelta(days=400):
                break
            following = self.next_after(at)
            if following - at < MIN_GAP:
                raise CronError(
                    f"cron {self.text!r} would scan every {following - at}: at least "
                    f"{int(MIN_GAP.total_seconds() // 60)} minutes between scheduled scans"
                )
            at = following


def _field(
    word: str, name: str, low: int, high: int, names: tuple[list[str], int] | None
) -> frozenset[int]:
    values: set[int] = set()
    for part in word.lower().split(","):
        base, _, step_text = part.partition("/")
        step = 1
        if step_text:
            if not step_text.isdigit() or int(step_text) < 1:
                raise CronError(f"{name}: step {step_text!r} must be a whole number of at least 1")
            step = int(step_text)
        if base == "*":
            first, last = low, high
        elif "-" in base:
            left, _, right = base.partition("-")
            first, last = (
                _value(left, name, low, high, names),
                _value(right, name, low, high, names),
            )
        else:
            first = _value(base, name, low, high, names)
            last = high if step_text else first  # "5/15": from 5, every 15
        if first > last:
            raise CronError(f"{name}: {part!r} runs backwards")
        values.update(range(first, last + 1, step))
    return frozenset(values)


def _value(text: str, name: str, low: int, high: int, names: tuple[list[str], int] | None) -> int:
    if names is not None and text in names[0]:
        return names[0].index(text) + names[1]
    if not text.isdigit():
        raise CronError(f"{name}: {text!r} is not a number")
    value = int(text)
    if not low <= value <= high:
        raise CronError(f"{name}: {value} is outside {low}-{high}")
    return value


def _first_of_next_month(at: datetime) -> datetime:
    return datetime(at.year + at.month // 12, at.month % 12 + 1, 1)


def _zone(text: str) -> tzinfo:
    if text.upper() in ("UTC", "Z"):
        return UTC
    offset = _OFFSET.fullmatch(text)
    if offset:
        sign = 1 if offset.group(1) == "+" else -1
        delta = timedelta(hours=int(offset.group(2)), minutes=int(offset.group(3)))
        return timezone(sign * delta)
    try:
        return ZoneInfo(text)
    except (ZoneInfoNotFoundError, ValueError):
        raise CronError(
            f"time zone {text!r}: an IANA name (Asia/Ho_Chi_Minh), UTC or an offset (+07:00); "
            "if the name is right, this machine lacks time zone data: pip install tzdata"
        ) from None
