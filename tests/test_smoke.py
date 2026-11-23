"""Smoke test: the package imports and exposes a version."""

import zues_scan


def test_version_exposed() -> None:
    assert zues_scan.__version__
