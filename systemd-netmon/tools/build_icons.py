#!/usr/bin/env python3
"""Regenerate static/icons.js from lucide-static SVGs (dev-time only; output is committed).
usage: python3 tools/build_icons.py /path/to/node_modules/lucide-static/icons"""
import json, os, re, sys
NAMES = ["terminal", "search", "pause", "play", "clock", "code-xml", "layers", "shield-alert", "cpu", "x",
         "zap", "triangle-alert", "power", "skull", "ban", "rotate-cw", "rotate-ccw", "circle-stop",
         "activity", "lock"]
src = sys.argv[1]
icons = {}
for n in NAMES:
    svg = open(os.path.join(src, n + ".svg")).read()
    icons[n] = re.sub(r"\s+", " ", re.search(r">\s*(.*)</svg>", svg, re.S).group(1)).strip()
out = os.path.join(os.path.dirname(__file__), "..", "static", "icons.js")
with open(out, "w") as fh:
    fh.write("/* Subset of Lucide icons (lucide-static 0.460.0, ISC License, https://lucide.dev). Vendored: no CDN. */\n")
    fh.write("window.NetmonIcons = (function () {\n  const I = %s;\n" % json.dumps(icons, indent=1))
    fh.write("""  function render(root) {
    (root || document).querySelectorAll('i[data-lucide]').forEach(function (el) {
      const body = I[el.getAttribute('data-lucide')];
      if (!body) return;
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      ['width', 'height'].forEach(function (a) { svg.setAttribute(a, '24'); });
      svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '2');
      svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
      svg.setAttribute('class', 'lucide ' + (el.getAttribute('class') || ''));
      svg.innerHTML = body;
      el.replaceWith(svg);
    });
  }
  return { render: render };
})();
""")
print("wrote", out, len(icons), "icons")
