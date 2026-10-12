"""Parse a targets file for `certfan check -f`."""
from __future__ import annotations

from typing import Iterator, Optional, Tuple


def parse_targets_file(path: str) -> list[Tuple[str, dict]]:
    """Return [(host[:port], overrides)] from a targets file.

    Format: one target per line (`host` or `host:port`). Blank lines and `#` comments
    are ignored. Optional trailing `warn_days=N` / `warn_pct=N` tokens override globals.
    """
    out: list[Tuple[str, dict]] = []
    with open(path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # strip inline comments after whitespace+#
            if " #" in line:
                line = line[: line.index(" #")].rstrip()
            parts = line.split()
            if not parts:
                continue
            target = parts[0]
            overrides: dict = {}
            for tok in parts[1:]:
                if "=" not in tok:
                    raise ValueError(f"{path}:{lineno}: unexpected token {tok!r} (expected key=value)")
                key, _, val = tok.partition("=")
                key = key.strip().lower()
                val = val.strip()
                if key in ("warn_days", "warn_pct"):
                    try:
                        overrides[key] = float(val)
                    except ValueError as e:
                        raise ValueError(f"{path}:{lineno}: invalid {key}={val!r}") from e
                else:
                    raise ValueError(f"{path}:{lineno}: unknown override {key!r} (want warn_days or warn_pct)")
            out.append((target, overrides))
    return out
