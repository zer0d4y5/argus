# Safe-code plants for the FP measurement eval. Every construct here is the
# CORRECT, non-vulnerable form of a weakness class the scanners look for. A
# PLANT-FP(id, CWE) label marks code that must NOT be flagged for that CWE; if
# a profile flags it, that is a measured false positive (reported per-profile
# in docs/coverage.md), never a hidden one. Precision is measured, not asserted.

import subprocess
import sqlite3
import hashlib


def safe_sql(conn: sqlite3.Connection, username: str):
    # PLANT-FP(py-safe-sql, CWE-89): parameterized query — the value is bound,
    # not interpolated, so this is not SQL injection.
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchall()


def safe_shell():
    # PLANT-FP(py-safe-shell, CWE-78): a constant argument vector, no shell,
    # no user input — not command injection.
    return subprocess.check_output(["uptime"], shell=False)


def safe_hash(data: bytes):
    # PLANT-FP(py-safe-hash, CWE-328): SHA-256 for integrity is a strong hash,
    # not a weak-crypto finding.
    return hashlib.sha256(data).hexdigest()
