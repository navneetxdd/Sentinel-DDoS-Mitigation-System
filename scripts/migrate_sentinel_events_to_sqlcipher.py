#!/usr/bin/env python3
"""
One-time migration: copy sentinel_events from plain SQLite to a new SQLCipher-encrypted file.

Usage:
  export SENTINEL_SQLCIPHER_PASSPHRASE='strong-secret'
  python scripts/migrate_sentinel_events_to_sqlcipher.py \\
    --plain /path/to/sentinel_events.db \\
    --out /path/to/sentinel_events.enc.db

Core logic lives in sentinel_db_migrate.py (also used by explain_api auto-migration).

Requires: pip install sqlcipher3 (and SQLCipher libraries on the host).
"""

from __future__ import annotations

import argparse
import os
import sys

# Repo root (parent of scripts/)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sentinel_db_migrate import is_plain_sqlite, migrate_plain_to_sqlcipher_file


def main() -> int:
    ap = argparse.ArgumentParser(description="Migrate plain sentinel_events.db to SQLCipher")
    ap.add_argument("--plain", required=True, help="Existing plain SQLite database path")
    ap.add_argument("--out", required=True, help="New encrypted database path")
    ap.add_argument(
        "--passphrase",
        help="SQLCipher passphrase (default: SENTINEL_SQLCIPHER_PASSPHRASE)",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Remove existing --out file before writing",
    )
    args = ap.parse_args()

    passphrase = (args.passphrase or os.environ.get("SENTINEL_SQLCIPHER_PASSPHRASE", "")).strip()
    if not passphrase:
        print(
            "[ERROR] Set --passphrase or SENTINEL_SQLCIPHER_PASSPHRASE",
            file=sys.stderr,
        )
        return 1

    if not os.path.isfile(args.plain):
        print(f"[ERROR] Plain database not found: {args.plain}", file=sys.stderr)
        return 1
    if not is_plain_sqlite(args.plain):
        print(
            f"[ERROR] File does not look like a plain SQLite database: {args.plain}",
            file=sys.stderr,
        )
        return 1

    if os.path.exists(args.out):
        if not args.force:
            print(f"[ERROR] Output exists: {args.out} (use --force to overwrite)", file=sys.stderr)
            return 1
        os.remove(args.out)

    try:
        n = migrate_plain_to_sqlcipher_file(args.plain, args.out, passphrase)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    print(f"[OK] Migrated {n} rows to {args.out}")
    print("Next: verify the app, then replace the live DB if in-place swap is intended.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
