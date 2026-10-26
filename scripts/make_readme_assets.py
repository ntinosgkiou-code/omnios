"""Re-creates docs/assets/demo.png for the README from the REAL output of `python -m omnios demo`.

Optional developer tool (needs Google Chrome for the screenshot). The lines are picked from what the demo prints when you run this
script; nothing is typed by hand and nothing is re-worded, only shortened where a line would be too wide.

    set PYTHONUTF8=1 && python scripts/make_readme_assets.py
"""
import html
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "assets", "demo.png")
CHROME = [os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
          r"C:\Program Files\Google\Chrome\Application\chrome.exe", "google-chrome", "chromium"]

# (section marker, [substrings of the demo lines to show, in order])
PICK = [
    ("2. A 4,000 EUR payment needs two different people", ["act-00001  PENDING_APPROVAL", "refused  the agent approving", "alice approved (1 of 2)",
                                                           "refused  alice approving a second time", "bob approved (2 of 2)"]),
    ("3. A 25,000 EUR payment is over the ceiling", ["act-00002  DENIED"]),
    ("5. Changing the rules needs a second admin", ["refused  admin-1 approving their own change", "admin-2 approves"]),
    ("7. Someone edits the pack", ["PROBLEM  record 5", "RESULT: FAILED"]),
    ("8b. The operator rewrites history", ["push acme-ap        -> auditor-witness  ALERT", "push acme-ap        -> insurer-witness  ALERT", "The auditor's check: FAILED", "PROBLEM  witness policy NOT met"]),
]


def run_demo():
    env = dict(os.environ, PYTHONUTF8="1")
    p = subprocess.run([sys.executable, "-m", "omnios", "demo"], cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0:
        sys.exit("the demo did not finish:\n" + p.stdout[-2000:] + p.stderr[-2000:])
    return p.stdout.splitlines()


def section(lines, marker):
    start = next(i for i, l in enumerate(lines) if marker in l)
    out = []
    for l in lines[start + 2:]:
        if l.startswith("-----"):
            break
        out.append(l)
    return out


def colour(line):
    t = line.strip()
    if re.search(r"refused|DENIED|PROBLEM|FAILED|ALERT", t):
        return "r"
    if re.search(r"PENDING|needs ", t):
        return "y"
    if re.search(r"approved|VERIFIED|applied|cosigned", t):
        return "g"
    return ""


def shorten(line, n=118):
    s = line.strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def main():
    lines = run_demo()
    rows = []
    for marker, wants in PICK:
        body = section(lines, marker)
        rows.append(("h", marker))
        for w in wants:
            hit = next((l for l in body if w in l), None)
            if hit is None:
                sys.exit(f"demo output no longer contains {w!r}: update PICK")
            rows.append((colour(hit), shorten(hit)))
    css = ("body{margin:0;background:#0d1117;color:#c9d1d9;font:15px/1.6 Consolas,'Cascadia Mono',monospace}"
           ".w{padding:26px 30px 30px}.d i{display:inline-block;width:13px;height:13px;border-radius:50%;margin-right:9px}"
           ".h{color:#58a6ff;font-weight:700;margin-top:14px}.g{color:#3fb950}.y{color:#e3a52f}.r{color:#ff6b61}.c{color:#7d8590;margin:14px 0 6px}")
    body = "".join(f'<div class="{c}">{html.escape(t)}</div>' for c, t in rows)
    page = (f"<!doctype html><meta charset=utf-8><style>{css}</style><div class=w><div class=d><i style='background:#ff5f56'></i>"
            f"<i style='background:#ffbd2e'></i><i style='background:#27c93f'></i></div><div class=c>$ python -m omnios demo   (real output, shortened)</div>{body}</div>")
    h = 90 + 30 * len(rows)
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "demo.html")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(page)
        chrome = next((c for c in CHROME if os.path.isfile(c) or c in ("google-chrome", "chromium")), None)
        if not chrome:
            sys.exit("Chrome not found: edit CHROME in scripts/make_readme_assets.py")
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
                        f"--window-size=1180,{h}", f"--screenshot={OUT}", "file:///" + f.replace("\\", "/")], capture_output=True)
    print("wrote", OUT, os.path.getsize(OUT) // 1024, "KB,", len(rows), "lines")


if __name__ == "__main__":
    main()
