"""Generate Zeekr EV brand images. Standard library only (no Pillow/numpy).

Renders a rounded-square tile with a vertical gradient and a bolt, using
scanline coverage so edges are anti-aliased at 1x resolution.
"""

import math
import pathlib
import struct
import zlib

BG_TOP = (0x1B, 0x46, 0x73)
BG_BOTTOM = (0x09, 0x1E, 0x36)
FG_COLOR = (0xFF, 0xFF, 0xFF)

BOLT = [
    (0.6451, 0.1465),
    (0.3320, 0.5570),
    (0.4883, 0.5570),
    (0.3910, 0.8590),
    (0.6840, 0.4430),
    (0.5270, 0.4430),
]

OUT = (
    pathlib.Path(__file__).resolve().parent.parent
    / "custom_components" / "zeekr_ev" / "brand"
)


def write_png(path, width, height, rows):
    raw = bytearray()
    for row in rows:
        raw.append(0)
        raw.extend(row)

    def chunk(tag, data):
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    pathlib.Path(path).write_bytes(png)


def add_span(cov, x0, x1):
    n = len(cov)
    i0 = max(int(math.floor(x0)), 0)
    i1 = min(int(math.ceil(x1)), n)
    for i in range(i0, i1):
        left = x0 if x0 > i else float(i)
        right = x1 if x1 < i + 1 else float(i + 1)
        if right > left:
            value = cov[i] + (right - left)
            cov[i] = 1.0 if value > 1.0 else value


def poly_spans(poly, y):
    xs = []
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > y) != (yj > y):
            xs.append((xj - xi) * (y - yi) / (yj - yi) + xi)
        j = i
    xs.sort()
    return [(xs[k], xs[k + 1]) for k in range(0, len(xs) - 1, 2)]


def rounded_rect_span(y, w, h, r):
    yc = y + 0.5
    if yc < r:
        dy = r - yc
        dx = r - math.sqrt(max(r * r - dy * dy, 0.0))
        return dx, w - dx
    if yc > h - r:
        dy = yc - (h - r)
        dx = r - math.sqrt(max(r * r - dy * dy, 0.0))
        return dx, w - dx
    return 0.0, float(w)


def lerp(a, b, t):
    return int(a + (b - a) * t + 0.5)


def render(w, h, radius, bolt_poly):
    rows = []
    for y in range(h):
        bg = [0.0] * w
        bx0, bx1 = rounded_rect_span(y, w, h, radius)
        add_span(bg, bx0, bx1)

        fg = [0.0] * w
        for (a, b) in poly_spans(bolt_poly, y + 0.5):
            add_span(fg, a, b)

        t = y / max(h - 1, 1)
        base = (
            lerp(BG_TOP[0], BG_BOTTOM[0], t),
            lerp(BG_TOP[1], BG_BOTTOM[1], t),
            lerp(BG_TOP[2], BG_BOTTOM[2], t),
        )

        row = bytearray()
        for x in range(w):
            a_bg = bg[x]
            if a_bg <= 0.002:
                row += b"\x00\x00\x00\x00"
                continue
            a_fg = fg[x]
            ratio = a_fg / a_bg
            if ratio > 1.0:
                ratio = 1.0
            row.append(lerp(base[0], FG_COLOR[0], ratio))
            row.append(lerp(base[1], FG_COLOR[1], ratio))
            row.append(lerp(base[2], FG_COLOR[2], ratio))
            row.append(int(a_bg * 255 + 0.5))
        rows.append(row)
    return rows


def bolt_in_box(poly, x0, y0, w, h):
    xs = [p[0] for p in poly]
    ys = [p[1] for p in poly]
    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)
    sx = w / (maxx - minx)
    sy = h / (maxy - miny)
    return [((x - minx) * sx + x0, (y - miny) * sy + y0) for x, y in poly]


# The bolt's own aspect ratio, used to size it inside a landscape logo.
BOLT_ASPECT = 0.494


def main():
    for size, name in ((256, "icon.png"), (512, "icon@2x.png"),
                       (256, "dark_icon.png"), (512, "dark_icon@2x.png")):
        poly = [(x * size, y * size) for x, y in BOLT]
        rows = render(size, size, int(size * 0.225), poly)
        write_png(OUT / name, size, size, rows)
        print(f"wrote {name} ({size}x{size})")

    for w, h, name in ((860, 400, "logo.png"), (1720, 800, "logo@2x.png")):
        bolt_h = h * 0.72
        bolt_w = bolt_h * BOLT_ASPECT
        poly = bolt_in_box(BOLT, (w - bolt_w) / 2, (h - bolt_h) / 2, bolt_w, bolt_h)
        rows = render(w, h, int(h * 0.22), poly)
        write_png(OUT / name, w, h, rows)
        print(f"wrote {name} ({w}x{h})")


if __name__ == "__main__":
    main()
