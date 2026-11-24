"""Landlock: a process confines itself to some folders, without being root (Linux 5.13+).

The child process that runs a plugin from another package (`process`) calls `confine()`
before importing it: from then on it — and every program it starts — can read only the
folders it was given (the system, Python, its own package, the templates of the scan),
and write only its temporary folder. The database, the service configuration, SSH
credentials and the CVE cache are outside them: opening one fails with "permission
denied". A confined process also cannot inspect processes outside its domain (ptrace,
/proc/<pid>/environ, /proc/<pid>/fd), so the service's own environment and open files
stay out of reach.

What Landlock does not restrict here: the network (TCP rules need ABI 4 and are not used:
a plugin must reach its targets), and walking paths (only opening them). On a kernel
without Landlock (or another operating system), `confine()` changes nothing and returns 0:
the caller decides what to say about it.

Standard library only (ctypes).
"""

from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Iterable

# System call numbers: the same on every architecture (they were added after the tables
# were unified).
_CREATE_RULESET, _ADD_RULE, _RESTRICT_SELF = 444, 445, 446
_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

EXECUTE = 1 << 0
WRITE_FILE = 1 << 1
READ_FILE = 1 << 2
READ_DIR = 1 << 3
REMOVE_DIR = 1 << 4
REMOVE_FILE = 1 << 5
MAKE_CHAR = 1 << 6
MAKE_DIR = 1 << 7
MAKE_REG = 1 << 8
MAKE_SOCK = 1 << 9
MAKE_FIFO = 1 << 10
MAKE_BLOCK = 1 << 11
MAKE_SYM = 1 << 12
REFER = 1 << 13  # ABI 2: link / rename across folders
TRUNCATE = 1 << 14  # ABI 3
IOCTL_DEV = 1 << 15  # ABI 5

_ABI1 = (1 << 13) - 1  # EXECUTE ... MAKE_SYM
READ = EXECUTE | READ_FILE | READ_DIR
# What a rule on a single file (not a folder) may grant.
_FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1  # __attribute__((packed)) in the kernel's header
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def abi() -> int:
    """The Landlock version this kernel offers; 0: none (or not Linux)."""
    if not sys.platform.startswith("linux"):
        return 0
    try:
        version = int(
            _libc().syscall(
                _CREATE_RULESET, None, ctypes.c_size_t(0), ctypes.c_uint32(_CREATE_RULESET_VERSION)
            )
        )
    except (OSError, AttributeError):
        return 0
    return version if version > 0 else 0


def handled(version: int) -> int:
    """Every file-system right the kernel's Landlock version can restrict."""
    rights = _ABI1
    if version >= 2:
        rights |= REFER
    if version >= 3:
        rights |= TRUNCATE
    if version >= 5:
        rights |= IOCTL_DEV
    return rights


def confine(read: Iterable[str], write: Iterable[str]) -> int:
    """Restrict this process, and everything it starts from now on, to reading under
    `read` and reading + writing under `write` (folders or files; ones that do not exist
    are skipped). Cannot be undone. Returns the Landlock version applied; 0 when the
    kernel has none (nothing was changed). Raises OSError if Landlock is there but the
    restriction could not be applied — the caller must not go on unconfined then."""
    version = abi()
    if not version:
        return 0
    libc = _libc()
    rights = handled(version)
    attr = _RulesetAttr(rights)
    ruleset = int(libc.syscall(_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0))
    if ruleset < 0:
        _fail("landlock_create_ruleset")
    try:
        for path in read:
            _allow(libc, ruleset, path, READ & rights)
        for path in write:
            _allow(libc, ruleset, path, rights)
        # Required for an unprivileged process; also means nothing it runs can gain
        # privileges (setuid programs, file capabilities).
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            _fail("prctl(PR_SET_NO_NEW_PRIVS)")
        if int(libc.syscall(_RESTRICT_SELF, ruleset, 0)) != 0:
            _fail("landlock_restrict_self")
    finally:
        os.close(ruleset)
    return version


def _allow(libc: ctypes.CDLL, ruleset: int, path: str, rights: int) -> None:
    try:
        fd = os.open(path, getattr(os, "O_PATH", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return  # not there: nothing to allow
    try:
        if not os.path.isdir(path):
            rights &= _FILE_RIGHTS
        rule = _PathBeneathAttr(rights, fd)
        if int(libc.syscall(_ADD_RULE, ruleset, _RULE_PATH_BENEATH, ctypes.byref(rule), 0)) != 0:
            _fail(f"landlock_add_rule({path})")
    finally:
        os.close(fd)


def _fail(what: str) -> None:
    err = ctypes.get_errno()
    raise OSError(err, f"{what}: {os.strerror(err)}")
