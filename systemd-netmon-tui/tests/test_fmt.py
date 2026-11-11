from netmontui.fmt import clip, fmt_bytes, fmt_kbps, layout_columns, sparkline, split_heights, wrap


def test_bytes_and_rates():
    assert fmt_bytes(None) == "n/a" and fmt_bytes(0) == "0 B" and fmt_bytes(512) == "512 B"
    assert fmt_bytes(1536) == "1.50 KB" and fmt_bytes(5 * 1024 ** 3) == "5.00 GB"
    assert fmt_kbps(None) == "n/a" and fmt_kbps(2048) == "2.00"


def test_sparkline():
    assert sparkline([], 10) == ""
    s = sparkline([0, 1, 2, 4, 8], 10)
    assert len(s) == 5 and s[0] == " " and s[-1] == "█"
    assert sparkline(list(range(100)), 12) == sparkline(list(range(88, 100)), 12)
    assert set(sparkline([1, 5, 9], 5, unicode_ok=False)) <= set(" .:-=+*#%@")


def test_clip():
    assert clip("abcdef", 4) == "abc…" and clip("abc", 4) == "abc" and clip("x", 0) == ""
    assert clip("a\x1b[31mb\nc", 20) == "a?[31mb c"  # control chars neutralised


def test_layout_columns_fit_and_drop():
    spec = [("a", 10, 1, 100), ("b", 10, 0, 50), ("c", 10, 1, 10)]
    cols = layout_columns(spec, 40)
    assert [c[0] for c in cols] == ["a", "b", "c"] and cols[-1][1] + cols[-1][2] == 40
    cols = layout_columns(spec, 25)
    assert [c[0] for c in cols] == ["a", "b"]           # lowest priority dropped first
    assert cols[-1][1] + cols[-1][2] <= 25
    cols = layout_columns(spec, 5)
    assert [c[0] for c in cols] == ["a"]                 # essentials never dropped


def test_split_heights():
    svc, sock = split_heights(45, 6)
    assert svc + sock == 40 and sock == 10
    svc, sock = split_heights(20, 50)
    assert svc >= 6 and sock >= 6 and svc + sock == 15


def test_wrap():
    assert wrap("aa bb cc", 5) == ["aa bb", "cc"]
    assert wrap("x" * 12, 5) == ["xxxxx", "xxxxx", "xx"]


def test_sparkline_common_scale():
    assert sparkline([10, 10], 5, peak=100) != sparkline([10, 10], 5)
    assert sparkline([100], 5, peak=100) == "█"
