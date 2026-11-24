"""Cron schedules, and the slots that keep scheduled scans from drifting (G23)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import ModuleType
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pytest

from zues_scan.server.config import Target, parse_every
from zues_scan.server.cron import Cron, CronError

NOW = datetime(2026, 11, 24, 3, 15, tzinfo=UTC)  # a Tuesday


def _has_zones() -> bool:
    try:
        ZoneInfo("Europe/Berlin")
    except ZoneInfoNotFoundError:
        return False
    return True


# Windows without the tzdata package (the core install): offsets still work, names do not.
needs_zones = pytest.mark.skipif(not _has_zones(), reason="no IANA time zone data here")


@pytest.fixture
def scheduler() -> ModuleType:
    pytest.importorskip("rq")  # the scheduler is part of zues-scan[server]
    from zues_scan.server import scheduler

    return scheduler


def fires(text: str, after: datetime, count: int = 3) -> list[str]:
    cron, out, at = Cron.parse(text), [], after
    for _ in range(count):
        at = cron.next_after(at)
        out.append(at.astimezone(cron.zone).strftime("%a %Y-%m-%d %H:%M %z"))
    return out


# --- the expression -----------------------------------------------------------------------------


def test_fields_lists_ranges_steps_and_names() -> None:
    assert fires("*/20 9-10 * * *", NOW) == [
        "Tue 2026-11-24 09:00 +0000",
        "Tue 2026-11-24 09:20 +0000",
        "Tue 2026-11-24 09:40 +0000",
    ]
    assert fires("0 2 * * sat", NOW, 2) == [
        "Sat 2026-11-28 02:00 +0000",
        "Sat 2026-12-05 02:00 +0000",
    ]
    assert (
        fires("0 2 * * 7", NOW, 1) == fires("0 2 * * 0", NOW, 1) == ["Sun 2026-11-29 02:00 +0000"]
    )
    assert fires("15 8 1,15 jan,jul *", NOW, 2) == [
        "Fri 2027-01-01 08:15 +0000",
        "Fri 2027-01-15 08:15 +0000",
    ]
    assert fires("0 12 * * mon-fri/2", NOW, 3) == [  # Mon, Wed, Fri
        "Wed 2026-11-25 12:00 +0000",
        "Fri 2026-11-27 12:00 +0000",
        "Mon 2026-11-30 12:00 +0000",
    ]


def test_day_of_month_or_day_of_week_when_both_are_set() -> None:
    # crontab(5): the 1st of the month AND every Monday, not "Mondays that are the 1st".
    assert fires("0 6 1 * mon", NOW, 3) == [
        "Mon 2026-11-30 06:00 +0000",
        "Tue 2026-12-01 06:00 +0000",
        "Mon 2026-12-07 06:00 +0000",
    ]


@needs_zones
def test_time_zones() -> None:
    assert fires("0 2 * * sat Asia/Ho_Chi_Minh", NOW, 1) == ["Sat 2026-11-28 02:00 +0700"]
    assert fires("0 2 * * sat +07:00", NOW, 1) == ["Sat 2026-11-28 02:00 +0700"]
    assert Cron.parse("0 2 * * sat Asia/Ho_Chi_Minh").next_after(NOW) == datetime(
        2026, 11, 27, 19, 0, tzinfo=UTC
    )


@needs_zones
def test_daylight_saving_time_fires_once_a_day() -> None:
    berlin = "30 2 * * * Europe/Berlin"
    # 29 March 2026: 02:00 -> 03:00, there is no 02:30; 25 October: 02:30 happens twice.
    spring = fires(berlin, datetime(2026, 3, 28, 12, 0, tzinfo=UTC), 3)
    autumn = fires(berlin, datetime(2026, 10, 24, 12, 0, tzinfo=UTC), 3)
    assert [f[:14] for f in spring] == ["Sun 2026-03-29", "Mon 2026-03-30", "Tue 2026-03-31"]
    assert [f[:14] for f in autumn] == ["Sun 2026-10-25", "Mon 2026-10-26", "Tue 2026-10-27"]


def test_a_leap_day_schedule() -> None:
    assert fires("0 0 29 2 *", NOW, 2) == [
        "Tue 2028-02-29 00:00 +0000",
        "Sun 2032-02-29 00:00 +0000",
    ]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("* * * * *", "at least 5 minutes between scheduled scans"),
        ("*/2 * * * *", "at least 5 minutes"),
        ("0,1 2 * * *", "at least 5 minutes"),
        ("0 2 * *", "five fields"),
        ("0 2 * * * * UTC", "five fields"),
        ("61 * * * *", "minute: 61 is outside 0-59"),
        ("0 5-1 * * *", "runs backwards"),
        ("0 2 * * monkey", "is not a number"),
        ("0 2 * * */0", "step '0'"),
        ("0 2 31 4 *", "never fires"),
        ("0 2 * * sat Mars/Base", "time zone 'Mars/Base'"),  # with or without data
    ],
)
def test_what_is_refused(text: str, message: str) -> None:
    with pytest.raises(CronError, match=message):
        Cron.parse(text)


def test_the_latest_firing() -> None:
    every_15 = Cron.parse("*/15 * * * *")
    assert every_15.latest_at_or_before(NOW) == NOW
    assert every_15.latest_at_or_before(NOW - timedelta(seconds=1)) == NOW - timedelta(minutes=15)
    assert Cron.parse("0 0 29 2 *").latest_at_or_before(NOW) == datetime(2024, 2, 29, tzinfo=UTC)


# --- slots: when a scheduled target is due ------------------------------------------------------


def every(text: str) -> Target:
    return Target(name="t", target="10.0.0.5", scope="s", every=parse_every(text))


def cron(text: str) -> Target:
    return Target(name="t", target="10.0.0.5", scope="s", cron=Cron.parse(text))


def test_every_keeps_to_its_slots_instead_of_drifting(scheduler: ModuleType) -> None:
    daily = every("24h")
    slot = datetime(2026, 11, 23, 2, 0, tzinfo=UTC)
    # The scan of 23 Nov waited 40 minutes in the queue; today's round comes 50 s late.
    late_round = slot + timedelta(days=1, seconds=50)
    ran = slot + timedelta(minutes=40)

    assert scheduler.decide(daily, ran, slot, late_round) == scheduler.Decision(
        True, slot + timedelta(days=1)
    )
    assert scheduler.decide(daily, ran, slot, slot + timedelta(hours=23, minutes=59)).due is False


def test_missed_slots_are_made_up_with_one_scan(scheduler: ModuleType) -> None:
    slot = datetime(2026, 11, 20, 2, 0, tzinfo=UTC)
    three_days_later = slot + timedelta(days=3, hours=5)  # the scheduler was down

    decision = scheduler.decide(every("24h"), None, slot, three_days_later)

    assert decision == scheduler.Decision(True, slot + timedelta(days=3))  # the latest, not three


def test_without_a_slot_the_run_history_decides(scheduler: ModuleType) -> None:
    hourly = every("1h")
    assert scheduler.decide(hourly, None, None, NOW) == scheduler.Decision(True, NOW)
    assert scheduler.decide(hourly, NOW - timedelta(minutes=30), None, NOW) == scheduler.Decision(
        False, None
    )


def test_a_cron_target_fires_once_per_firing(scheduler: ModuleType) -> None:
    saturday = cron("0 2 * * sat")
    fired = datetime(2026, 11, 21, 2, 0, tzinfo=UTC)
    assert scheduler.decide(saturday, None, fired, NOW).due is False  # Tuesday: done for this week
    next_one = datetime(2026, 11, 28, 2, 0, tzinfo=UTC)
    assert scheduler.decide(
        saturday, None, fired, next_one + timedelta(minutes=1)
    ) == scheduler.Decision(True, next_one)


def test_a_cron_target_added_after_its_time_waits_for_the_next(scheduler: ModuleType) -> None:
    saturday = cron("0 2 * * sat")
    last_firing = datetime(2026, 11, 21, 2, 0, tzinfo=UTC)

    added = scheduler.decide(saturday, None, None, NOW)

    assert added == scheduler.Decision(False, last_firing)  # recorded: the next Saturday is due
    just_after = last_firing + timedelta(minutes=10)  # e.g. Redis emptied by a restart
    assert scheduler.decide(saturday, None, None, just_after) == scheduler.Decision(
        True, last_firing
    )
    ran = last_firing + timedelta(minutes=5)
    assert scheduler.decide(saturday, ran, None, just_after) == scheduler.Decision(
        False, last_firing
    )
