"""Pull API routes and client constants out of a Zeekr app APK.

Why this exists: several questions about this platform cannot be answered from
public sources — China's IDaaS ``tspCode`` route, the host it lives on, and the
login ``identityType`` the current app uses.  All three are *strings inside the
shipped app*, so an APK answers them without any traffic capture.

The APK is never executed and never modified: it is read as a zip, and every
``.dex``/``.so``/``.json`` entry is scanned for printable ASCII runs that look
like a route, a host or a client constant.  Standard library only — this project
has no network and cannot install packages.

Usage:
    python tools/inspect_apk.py path/to/zeekr.apk
    python tools/inspect_apk.py path/to/zeekr.apk --grep tspCode
    python tools/inspect_apk.py path/to/zeekr.apk --min-length 12
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import zipfile

# Strings that would answer an open question.  Each entry is a label and the
# pattern to look for in the extracted text.
INTERESTING = (
    ("route", re.compile(r"/(?:ms|zeekrlife|zeekr-cuc|user|auth)[A-Za-z0-9./_{}-]*")),
    ("host", re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.zeekrlife\.com\b")),
    ("host", re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.zeekr(?:line)?\.com\b")),
    ("identity", re.compile(r"identityType|loginBy\w+|checkUser\w*|tspCode\w*")),
    ("appid", re.compile(r"[A-Z]{4,8}(?:CN|SEA|EU|LA)?CH001M\d{4}")),
    ("header", re.compile(r"x-(?:app|api|vin|project|device|p)[a-z-]*", re.I)),
)

# Readable runs long enough to hold a route but short enough to skip junk.
_RUN = re.compile(rb"[\x20-\x7e]{6,400}")
# DEX stores UTF-8 modified encoding, so non-ASCII bytes are kept out of the
# scan deliberately: routes and host names in this API are ASCII.
_TEXT_ENTRIES = (".dex", ".json", ".so", ".txt", ".xml", ".properties")


def scan(apk: pathlib.Path) -> dict[str, set[str]]:
    """Return every interesting string found, keyed by its label."""
    found: dict[str, set[str]] = {label: set() for label, _ in INTERESTING}
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if not info.filename.lower().endswith(_TEXT_ENTRIES):
                continue
            if info.file_size > 200 * 1024 * 1024:
                continue
            blob = archive.read(info)
            for match in _RUN.finditer(blob):
                text = match.group().decode("ascii", "ignore")
                for label, pattern in INTERESTING:
                    for hit in pattern.findall(text):
                        found[label].add(hit if isinstance(hit, str) else hit[0])
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=pathlib.Path)
    parser.add_argument("--grep", default=None,
                        help="only report strings containing this substring")
    parser.add_argument("--limit", type=int, default=400,
                        help="max strings to print per label")
    args = parser.parse_args(argv)

    if not args.apk.is_file():
        print(f"not a file: {args.apk}", file=sys.stderr)
        return 2

    found = scan(args.apk)
    needle = args.grep.lower() if args.grep else None
    for label, values in found.items():
        items = sorted(
            v for v in values if needle is None or needle in v.lower()
        )
        if not items:
            continue
        print(f"\n=== {label} ({len(items)}) ===")
        for value in items[: args.limit]:
            print(" ", value)
        if len(items) > args.limit:
            print(f"  … {len(items) - args.limit} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
