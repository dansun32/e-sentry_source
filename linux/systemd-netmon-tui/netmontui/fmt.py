"""Pure formatting/layout helpers (no curses import, fully unit-testable)."""
from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

SPARK_UNICODE = " ▁▂▃▄▅▆▇█"
SPARK_ASCII = " .:-=+*#%@"


def fmt_bytes(n: Optional[float]) -> str:
    if n is None:
        return "n/a"
    if n <= 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d B" % n) if unit == "B" else ("%.2f %s" % (n, unit))
        n /= 1024.0
    return "?"


def fmt_kbps(bps: Optional[float]) -> str:
    return "n/a" if bps is None else "%.2f" % (bps / 1024.0)


def sparkline(hist: Sequence[float], width: int, unicode_ok: bool = True,
              peak: Optional[float] = None) -> str:
    """peak: common scale (e.g. the busiest unit's max) so bars compare across rows."""
    chars = SPARK_UNICODE if unicode_ok else SPARK_ASCII
    h = list(hist)[-width:] if width > 0 else []
    if not h:
        return ""
    mx = max(max(h), peak or 0, 1.0)
    top = len(chars) - 1
    return "".join(chars[min(int(round(v / mx * top)), top)] if v > 0 else chars[0] for v in h)


def clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    text = str(text).replace("\n", " ").replace("\t", " ")
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text if len(text) <= width else (text[: width - 1] + "…" if width > 1 else text[:width])


def layout_columns(spec: Sequence[Tuple[str, int, int, int]], width: int) -> List[Tuple[str, int, int]]:
    """spec: (key, min_width, flex_weight, priority). Lower priority is dropped first when
    space runs out. Returns [(key, x, w)] in original order, one space between columns."""
    cols = list(spec)
    while cols:
        need = sum(c[1] for c in cols) + (len(cols) - 1)
        if need <= width:
            break
        drop = min(cols, key=lambda c: c[3])
        if drop[3] >= 100:  # never drop essentials; just squeeze
            break
        cols.remove(drop)
    spare = max(0, width - (sum(c[1] for c in cols) + len(cols) - 1))
    weight = sum(c[2] for c in cols) or 1
    out, x, given = [], 0, 0
    flex_cols = [c for c in cols if c[2] > 0]
    for c in cols:
        extra = 0
        if c[2] > 0:
            extra = spare * c[2] // weight
            if c is flex_cols[-1]:
                extra = spare - given
            given += extra
        w = c[1] + extra
        out.append((c[0], x, w))
        x += w + 1
    return out


def split_heights(h: int, n_sockets: int) -> Tuple[int, int]:
    """Rows for the services pane and the sockets pane (both include their 3 chrome rows)."""
    body = max(0, h - 5)  # header(1) + summary(2) + status(1) + footer(1)
    sock = max(6, min(n_sockets + 4, body // 3))
    svc = body - sock
    if svc < 6:
        svc = max(0, body - 6)
        sock = body - svc
    return svc, sock


def wrap(text: str, width: int) -> List[str]:
    out: List[str] = []
    for para in str(text).split("\n"):
        line = ""
        for word in para.split(" "):
            while len(word) > width:
                if line:
                    out.append(line)
                    line = ""
                out.append(word[:width])
                word = word[width:]
            if not line:
                line = word
            elif len(line) + 1 + len(word) <= width:
                line += " " + word
            else:
                out.append(line)
                line = word
        out.append(line)
    return out
