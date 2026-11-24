"""JSON for what crosses a process boundary: third-party plugins run in a child (G25).

`encode` turns the schema's dataclasses (ScanTarget, Asset, ScanResult, ScanProfile, ...)
into JSON values. `decode` builds them back from what a child process sent, checking every
field against the dataclass's type hints: the child runs third-party code, so its reply is
untrusted input, like a tool's output. A field that is not in the dataclass, a value of
the wrong type, a missing required field: refused, with where it was.

Standard library only.
"""

from __future__ import annotations

import dataclasses
import enum
import types
import typing
from typing import Any, get_args, get_origin, get_type_hints


class WireError(ValueError):
    """What a process sent does not have the shape it must have."""


def encode(value: Any) -> Any:
    """A JSON value for `value` (dataclasses, enums, lists, tuples, sets, dicts)."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: encode(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bool) or value is None or isinstance(value, (str, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [encode(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(encode(v) for v in value)
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise WireError("only text keys can be sent")
        return {k: encode(v) for k, v in value.items()}
    raise WireError(f"a {type(value).__name__} cannot be sent")


_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    if cls not in _HINTS:
        _HINTS[cls] = get_type_hints(cls)
    return _HINTS[cls]


def decode(tp: Any, data: Any, where: str = "reply") -> Any:
    """`data` (parsed JSON) as a value of type `tp`, checked all the way down."""
    origin = get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        options = get_args(tp)
        if data is None:
            if type(None) in options:
                return None
            raise WireError(f"{where}: a value is required")
        errors = []
        for option in options:
            if option is type(None):
                continue
            try:
                return decode(option, data, where)
            except WireError as exc:
                errors.append(str(exc))
        raise WireError(errors[0] if len(errors) == 1 else f"{where}: {'; '.join(errors)}")
    if origin is tuple:
        items = _list(data, where)
        args = get_args(tp)
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(decode(args[0], v, f"{where}[{i}]") for i, v in enumerate(items))
        if len(items) != len(args):
            raise WireError(f"{where}: {len(args)} items expected, not {len(items)}")
        return tuple(
            decode(a, v, f"{where}[{i}]") for i, (a, v) in enumerate(zip(args, items, strict=True))
        )
    if origin is list:
        (arg,) = get_args(tp)
        return [decode(arg, v, f"{where}[{i}]") for i, v in enumerate(_list(data, where))]
    if origin in (set, frozenset):
        (arg,) = get_args(tp)
        return {decode(arg, v, f"{where}[{i}]") for i, v in enumerate(_list(data, where))}
    if origin is dict:
        key, value = get_args(tp)
        if key is not str:
            raise WireError(f"{where}: only text keys are supported")
        mapping = _dict(data, where)
        return {k: decode(value, v, f"{where}[{k!r}]") for k, v in mapping.items()}
    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        return _dataclass(tp, data, where)
    if isinstance(tp, type) and issubclass(tp, enum.Enum):
        try:
            return tp(data)
        except (ValueError, TypeError):
            known = ", ".join(repr(m.value) for m in tp)
            raise WireError(f"{where}: {data!r} is not one of {known}") from None
    if tp is bool:
        if isinstance(data, bool):
            return data
        raise WireError(f"{where}: true or false expected")
    if tp is int:
        if isinstance(data, int) and not isinstance(data, bool):
            return data
        raise WireError(f"{where}: a whole number expected")
    if tp is float:
        if isinstance(data, (int, float)) and not isinstance(data, bool):
            return float(data)
        raise WireError(f"{where}: a number expected")
    if tp is str:
        if isinstance(data, str):
            return data
        raise WireError(f"{where}: text expected")
    raise WireError(f"{where}: {tp!r} cannot be received")


def _list(data: Any, where: str) -> list[Any]:
    if not isinstance(data, list):
        raise WireError(f"{where}: a list expected")
    return data


def _dict(data: Any, where: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise WireError(f"{where}: an object expected")
    return data


def _dataclass(cls: type, data: Any, where: str) -> Any:
    mapping = _dict(data, where)
    hints = _hints(cls)
    fields = [f for f in dataclasses.fields(cls) if f.init]
    unknown = sorted(set(mapping) - {f.name for f in fields})
    if unknown:
        raise WireError(f"{where}: unknown field(s) {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for f in fields:
        if f.name in mapping:
            values[f.name] = decode(hints[f.name], mapping[f.name], f"{where}.{f.name}")
        elif f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            raise WireError(f"{where}: {f.name} is missing")
    try:
        return cls(**values)
    except Exception as exc:  # noqa: BLE001 - the dataclass's own checks (__post_init__)
        raise WireError(f"{where}: {exc}") from None
