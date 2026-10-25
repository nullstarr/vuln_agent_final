#!/usr/bin/env python3
"""
Builds the complete demo video from code - no manual recording needed.

Was passiert:
  1. Titelkarten (Pillow)            -> video_cards/*.png
  2. Terminal scenes                  -> real runs of main.py (triage, Log4Shell,
                                        timeline, evidence trail), line by line "played back"
  3. Narration voice (Piper)          -> narration/*.mp3   (only with --regen-narration)
  4. Schnitt (ffmpeg)                 -> video/build/demo.mp4

Aufruf:
  python3 video/make_video.py                      # nutzt vorhandene narration/*.mp3
  python3 video/make_video.py --regen-narration --piper-model PFAD/en-us-libritts-high.onnx

Ehrlichkeit zum Inhalt:
  - The terminal sections show the REAL output of main.py in example mode
    (LLM_PROVIDER=rule_based), shortened to the header + 'out:' line per step.
  - The numbers on the measurement card come verbatim from evaluation/RESULTS.md (test half).
  - The Zetaris scene is a fact card from the real live run (check_zetaris.py).
  - The viewer scene uses your screenshot; the browser bar with
    tabs/bookmarks is cropped off. Replace video/assets/viewer.png
    with a new screenshot if you want to show the 3-column view.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CARD_DIR = os.path.join(ROOT, "video_cards")
NARRATION_DIR = os.path.join(ROOT, "narration")
BUILD_DIR = os.path.join(HERE, "build")
ASSETS_DIR = os.path.join(HERE, "assets")

W, H = 1920, 1080
BG = (15, 17, 21)
PANEL = (26, 29, 36)
TEXT = (232, 232, 234)
MUTED = (154, 160, 171)
GREEN = (61, 220, 132)
AMBER = (240, 180, 41)
RED = (239, 68, 68)
BORDER = (42, 46, 55)

FONT_DIR = "/usr/share/fonts/truetype/dejavu"


def font(name, size):
    return ImageFont.truetype(os.path.join(FONT_DIR, name), size)


F_TITLE = font("DejaVuSans-Bold.ttf", 76)
F_TITLE_MED = font("DejaVuSans-Bold.ttf", 58)
F_SUB = font("DejaVuSans.ttf", 34)
F_SMALL = font("DejaVuSans.ttf", 26)
F_MONO_SM = font("DejaVuSansMono.ttf", 24)
F_TERM = font("DejaVuSansMono.ttf", 26)
F_TERM_B = font("DejaVuSansMono-Bold.ttf", 26)

# ---------------------------------------------------------------------------
# Content: narration texts + which image belongs to which section
# ---------------------------------------------------------------------------

from script import SEGMENTS  # noqa: E402  (Sprechtexte: video/script.py)

# ---------------------------------------------------------------------------
# Zeichen-Helfer
# ---------------------------------------------------------------------------


def canvas():
    img = Image.new("RGB", (W, H), BG)
    return img, ImageDraw.Draw(img)


def center(draw, y, text, fnt, fill=TEXT):
    box = draw.textbbox((0, 0), text, font=fnt)
    draw.text(((W - (box[2] - box[0])) / 2, y), text, font=fnt, fill=fill)
    return y + (box[3] - box[1])


def wrapped(draw, y, text, fnt, fill, width, gap=14):
    for line in textwrap.wrap(text, width=width):
        y = center(draw, y, line, fnt, fill) + gap
    return y


def bar(draw, y, color, width=120, height=6):
    x0 = (W - width) / 2
    draw.rectangle([x0, y, x0 + width, y + height], fill=color)


import textwrap  # noqa: E402  (bewusst nach den Helfern, nur dort genutzt)


def make_cards():
    os.makedirs(CARD_DIR, exist_ok=True)

    img, d = canvas()
    center(d, 380, "Vulnerability Conflict Resolver", F_TITLE)
    bar(d, 480, GREEN)
    center(d, 540, "Open Agent Hackathon 2026 — Track: The Agent That Can Explain Why", F_SUB, MUTED)
    img.save(os.path.join(CARD_DIR, "01_opening.png"))

    # Only verifiable facts about Equifax - the "14 applications" come from OUR
    # simulated ticket and do not belong on this card.
    img, d = canvas()
    center(d, 260, "2017", F_TITLE, AMBER)
    y = center(d, 400, "Equifax: about 147 million people affected", F_TITLE_MED)
    bar(d, y + 40, RED)
    wrapped(d, y + 90,
            "A fix for the Apache Struts flaw had been public for months. "
            "The breach came through one unpatched system: a consumer dispute portal.",
            F_SUB, MUTED, 58)
    center(d, 900, "CVE-2017-5638  ·  CVSS 9.8  ·  Apache Struts", F_MONO_SM, MUTED)
    img.save(os.path.join(CARD_DIR, "02_equifax.png"))

    img, d = canvas()
    center(d, 460, "Live Demo", F_TITLE)
    bar(d, 560, GREEN)
    center(d, 620, "Four agents. A real rejection. A real revision.", F_SUB, MUTED)
    img.save(os.path.join(CARD_DIR, "03_live_demo_intro.png"))

    # Zetaris: facts from the real live run of check_zetaris.py (23 Oct 2026), no invented numbers.
    img, d = canvas()
    center(d, 150, "Data layer: Zetaris", F_TITLE_MED)
    bar(d, 240, GREEN)
    lines = ["NVD entries, vendor changelogs and internal tickets are REST tables",
             "A SQL view joins them; the tool reads each case with one SQL call",
             "Checked live on a local Zetaris: 17 cases, identical to the file run",
             "Files stay as fallback. Limit: one local instance, simulated data"]
    y = 330
    for ln in lines:
        center(d, y, ln, F_SUB, MUTED)
        y += 110
    img.save(os.path.join(CARD_DIR, "08_zetaris.png"))

    # Measurement: numbers verbatim from evaluation/RESULTS.md (test half, never used for tuning).
    img, d = canvas()
    center(d, 110, "Certainty check, test half (never tuned on)", F_TITLE_MED)
    center(d, 200, "hedged text wrongly rated certain  |  harmless false alarms", F_SMALL, MUTED)
    rows = [("Rules only", "55 / 56 missed", "0 / 86", RED),
            ("Model, prompt v1", "1 / 56 missed", "50 / 86", AMBER),
            ("Model, prompt v2 (default)", "3 / 56 missed", "about 9-10 / 86", GREEN),
            ("Model, prompt v3 (not adopted)", "1 / 56 missed", "22 / 86", MUTED)]
    y = 300
    for name, miss, fa, col in rows:
        d.rounded_rectangle([200, y, 1720, y + 110], radius=14, fill=PANEL, outline=BORDER, width=2)
        d.text((240, y + 30), name, font=F_SUB, fill=TEXT)
        d.text((960, y + 30), miss, font=F_SUB, fill=col)
        d.text((1360, y + 30), fa, font=F_SUB, fill=MUTED)
        y += 135
    center(d, 880, "Own corpus of 286 sentences, written by the rule author. Two identical runs differ by 1-4 texts.",
           F_SMALL, MUTED)
    center(d, 925, "Pre-registered adoption rule: at most 3/56 missed and 6/86 false alarms. v3 failed it.",
           F_SMALL, MUTED)
    img.save(os.path.join(CARD_DIR, "09_measure.png"))

    img, d = canvas()
    center(d, 250, "Honest limits", F_TITLE_MED)
    bar(d, 340, RED)
    lim = ["Internal tickets and timelines are simulated (NVD and vendor texts are real or paraphrased).",
           "The evaluation corpus is our own - not independent data.",
           "On 3 real advisories our fix rule missed one wording (known gap, not patched).",
           "No users yet. Three rounds of AI review found false \"resolved\" cases; fixed and tested, but rules stay brittle.",
           "If a vendor never answers, the system can never say \"resolved\" - by design."]
    y = 420
    for t in lim:
        y = wrapped(d, y, t, F_SUB, MUTED, 62, gap=10) + 22
    img.save(os.path.join(CARD_DIR, "10_limits.png"))

    img, d = canvas()
    center(d, 340, "Vulnerability Conflict Resolver", F_TITLE_MED)
    bar(d, 430, GREEN)
    center(d, 500, "Track: The Agent That Can Explain Why", F_SUB, TEXT)
    center(d, 560, "Sponsor tech: Meterless (World Model) · Cursor", F_SUB, MUTED)
    center(d, 680, "github.com/nullstarr/vuln_agent", F_MONO_SM, MUTED)
    img.save(os.path.join(CARD_DIR, "07_closing.png"))
    print("Title cards created")


# ---------------------------------------------------------------------------
# Terminal "playback" from real runs
# ---------------------------------------------------------------------------

HEADER_RE = re.compile(r"^\[[^\]]+\]\s+(\S+)\s+\|\s+(.+?)\s+->\s+(\S+)\s+\|\s+(status=\S+)")

_RUN_CACHE = {}


def run_main(args_list):
    """Runs main.py in a throwaway copy (logs/ and the real project's process history stay
    untouched) and returns stdout. Results are cached per call."""
    key = tuple(args_list)
    if key in _RUN_CACHE:
        return _RUN_CACHE[key]
    tmp = tempfile.mkdtemp(prefix="vp_")
    try:
        work = os.path.join(tmp, "p")
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
            ".git", "logs", "build", "__pycache__", "video_cards", "narration", "*.mp4"))
        os.makedirs(os.path.join(work, "logs"))
        # Default: example mode (no AI). With AI:  VIDEO_TRACE_PROVIDER=ollama python3 video/make_video.py
        provider = os.environ.get("VIDEO_TRACE_PROVIDER", "rule_based")
        env = dict(os.environ, LLM_PROVIDER=provider, PYTHONUNBUFFERED="1")
        run = subprocess.run([sys.executable, "main.py", *args_list],
                             cwd=work, env=env, capture_output=True, text=True)
        if run.returncode != 0:
            tail = "\n".join(run.stderr.strip().splitlines()[-3:])
            sys.exit(f"main.py {' '.join(args_list)} ist mit LLM_PROVIDER={provider} fehlgeschlagen:\n{tail}")
        _RUN_CACHE[key] = run.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return _RUN_CACHE[key]


def parse_trace(out):
    entries, cur = [], None
    for line in out.splitlines():
        m = HEADER_RE.match(line)
        if m:
            cur = dict(agent=m.group(1), action=m.group(2), target=m.group(3),
                       status=m.group(4), out="")
            entries.append(cur)
        elif cur is not None and line.startswith("    out:"):
            cur["out"] = line[len("    out:"):].strip()
        elif line.startswith("--- REPORT ---"):
            break
    return entries


def section(out, start_marker, stop_prefixes=("--- ", "TRIAGE", "TIMELINE"), stop_blank=False):
    """Lines from the line with start_marker up to (but excluding) the next section heading
    or the first blank line (whichever comes first, after the header)."""
    lines = out.splitlines()
    for i, l in enumerate(lines):
        if start_marker in l:
            res = [l]
            for nxt in lines[i + 1:]:
                if any(nxt.startswith(p) for p in stop_prefixes) or re.match(r"\d+ Fall", nxt):
                    break
                if stop_blank and not nxt.strip() and len(res) > 3:
                    break
                res.append(nxt)
            while res and not res[-1].strip():
                res.pop()
            return res
    sys.exit(f"section '{start_marker}' missing in main.py output - format changed?")


def trunc(s, n=98):
    return s if len(s) <= n else s[: n - 1] + "…"


def entry_lines(e):
    action = e["action"]
    color = TEXT
    if "reject" in action:
        color = RED
    elif "approve" in action:
        color = GREEN
    head = trunc(f"{e['agent']} | {action} -> {e['target']}   {e['status']}")
    lines = [(head, color)]
    if e["out"]:
        lines.append((trunc("    " + e["out"]), MUTED))
    return lines


def draw_terminal(command, lines, annotation=None, dense=False):
    img, d = canvas()
    x0, y0, x1, y1 = 110, 70, 1810, 950
    d.rounded_rectangle([x0, y0, x1, y1], radius=18, fill=PANEL, outline=BORDER, width=2)
    for i, c in enumerate((RED, AMBER, GREEN)):
        d.ellipse([x0 + 26 + i * 34, y0 + 22, x0 + 44 + i * 34, y0 + 40], fill=c)
    d.text((x0 + 150, y0 + 17), "vuln_agent — terminal", font=F_SMALL, fill=MUTED)
    d.line([x0, y0 + 66, x1, y0 + 66], fill=BORDER, width=2)
    y = y0 + 90
    d.text((x0 + 34, y), "$ " + command, font=F_TERM_B, fill=GREEN)
    y += 54 if not dense else 46
    fnt, step = (F_TERM_D, 30) if dense else (F_TERM, 36)
    for text, color in lines:
        d.text((x0 + 34, y), text, font=fnt, fill=color)
        y += step
    if y > y1 + 4:
        sys.exit(f"terminal scene too long for the image (ends at y={y}). Choose fewer lines.")
    if annotation:
        center(d, 985, annotation, F_SMALL, AMBER)
    return img


F_TERM_D = font("DejaVuSansMono.ttf", 21)


def wrap_lines(text, color, width, indent=""):
    parts = textwrap.wrap(text, width=width, subsequent_indent=indent + "  ") or [""]
    return [(indent + p if i == 0 else p, color) for i, p in enumerate(parts)]


def reveal(cmd, groups, dense=False, annotation=None):
    """Image sequence: empty terminal, then one group more per group; the last image optionally with an annotation."""
    frames = [draw_terminal(cmd, [], dense=dense)]
    shown = []
    for g in groups:
        shown = shown + g
        frames.append(draw_terminal(cmd, shown, dense=dense))
    if annotation:
        frames[-1] = draw_terminal(cmd, shown, annotation=annotation, dense=dense)
    return frames


def terminal_frames(kind):
    """Returns a list of images - each shows one step more. Everything comes from real runs."""
    if kind == "triage":
        out = run_main([])
        rows = section(out, "TRIAGE - most urgent first", stop_blank=True)
        groups = [[(trunc(r, 124), RED if " unresolved" in r else GREEN if " resolved" in r else MUTED)]
                  for r in rows]
        # show the header (3 lines) together, the lines after bundled in steps of 3
        head, body = [g[0] for g in groups[:3]], [g[0] for g in groups[3:]]
        steps = [head] + [body[i:i + 3] for i in range(0, len(body), 3)]
        return reveal("python3 main.py", steps, dense=True,
                      annotation="Real run, example mode (no AI). Internal tickets are simulated.")

    if kind == "hook":
        case = "CVE-2021-44228"
        out = run_main(["--case", case])
        want = ("build_draft", "reject")
        entries = [e for e in parse_trace(out) if any(w in e["action"] for w in want)]
        groups = [entry_lines(e) for e in entries]
        m = re.search(r"^Confidence:\s*(.+)$", out, re.M)       # real line from the report
        final = [("Final: confidence " + (m.group(1).strip() if m else "see report"), RED)]
        return reveal(f"python3 main.py --case {case}", groups + [final],
                      annotation="Real run. The internal ticket is simulated.")

    if kind == "log4shell":
        case = "CVE-2021-44228"
        cmd = f"python3 main.py --case {case}"
        entries = [e for e in parse_trace(run_main(["--case", case])) if "build_world_model" not in e["action"]]
        return reveal(cmd, [entry_lines(e) for e in entries])

    if kind == "next_steps":
        case = "CVE-2021-44228"
        out = run_main(["--case", case])
        sec = section(out, "--- WHAT WOULD RESOLVE THIS ---")
        groups = [[("--- WHAT WOULD RESOLVE THIS ---", AMBER)]]
        for l in sec[1:]:
            groups.append(wrap_lines(l, TEXT, 100))
        return reveal(f"python3 main.py --case {case}   # report, last part", groups,
                      annotation="Real output. The ticket behind it is simulated.")

    if kind == "timeline":
        out = run_main(["--case", "CVE-2017-5638"])
        sec = section(out, "TIMELINE CVE-2017-5638", stop_prefixes=("--- ", "TRIAGE", "TIMELINE "))
        # header: title + note + table header + separator, then per day (line + reason), the engine line at the end
        lines = [l for l in sec if l.strip()]
        title, rest = lines[0], lines[1:]
        groups = [wrap_lines(title, TEXT, 120)]
        i = 0
        # note (parenthesis line) and table header
        while i < len(rest) and not re.match(r"\s*\d+\s+\d{4}-", rest[i]):
            groups[0] += wrap_lines(rest[i].rstrip(), MUTED, 120)
            i += 1
        while i < len(rest):
            l = rest[i]
            if re.match(r"\s*\d+\s+\d{4}-", l):
                col = AMBER if "<- changed" in l else TEXT
                g = wrap_lines(l.rstrip(), col, 120, indent="")
                if i + 1 < len(rest) and not re.match(r"\s*\d+\s+\d{4}-", rest[i + 1]) \
                        and not rest[i + 1].startswith("Meterless"):
                    g += wrap_lines(rest[i + 1].strip(), MUTED, 112, indent=" " * 6)
                    i += 1
                groups.append(g)
            else:
                groups.append(wrap_lines(l.strip(), GREEN, 120))
            i += 1
        return reveal("python3 main.py --case CVE-2017-5638", groups, dense=True,
                      annotation="Real run on a SIMULATED timeline (dates and tickets invented).")

    if kind == "meterless":
        case = "CVE-2021-44228"
        out = run_main(["--case", case])
        sec = section(out, "--- EVIDENCE TRAIL (Meterless World Model) ---", stop_prefixes=("--- ",))
        groups = [[(sec[0], AMBER)]] + [wrap_lines(l, TEXT, 104) for l in sec[1:] if l.strip()]
        return reveal(f"python3 main.py --case {case}   # report, evidence trail", groups,
                      annotation="Meterless World Model (unmodified reference engine, Node bridge). Python port without Node.")

    if kind == "zetaris":
        case = "CVE-2014-0160"
        cmd = f"python3 main.py --case {case} --source zetaris"
        out = run_main(["--case", case, "--source", "zetaris"])
        dl = section(out, "--- DATA LAYER ---", stop_prefixes=("--- ",))
        ex = section(out, "--- EXPLOITATION SIGNAL ---", stop_prefixes=("--- ",))
        g1 = [[(dl[0], AMBER)]] + [wrap_lines(l.rstrip(), TEXT, 112) for l in dl[1:] if l.strip()]
        g2 = [[(ex[0], AMBER)]] + [wrap_lines(l.rstrip(), RED if "KNOWN TO BE" in l else TEXT, 112) for l in ex[1:4] if l.strip()]
        return reveal(cmd, g1 + g2, dense=True,
                      annotation="Real run against a local Zetaris. The signal changes the urgency, not the verdict.")

    sys.exit(f"Unknown terminal scene: {kind}")


def viewer_frame():
    src = os.path.join(ASSETS_DIR, "viewer.png")
    if not os.path.exists(src):
        sys.exit(f"Missing: {src} - put a screenshot of the viewer page there.")
    im = Image.open(src).convert("RGB")
    # Full-screen screenshot (16:9)? Then crop off the browser bar (tabs, address bar, bookmarks) at the
    # top. An already-cropped image (different aspect ratio) stays unchanged.
    if abs(im.width / im.height - 16 / 9) < 0.02:
        im = im.crop((0, int(im.height * 152 / 1440), im.width, im.height))
    scale = min(W / im.width, H / im.height)
    im = im.resize((int(im.width * scale), int(im.height * scale)), Image.LANCZOS)
    img, _ = canvas()
    img.paste(im, ((W - im.width) // 2, (H - im.height) // 2))
    return [img]


# ---------------------------------------------------------------------------
# Stimme
# ---------------------------------------------------------------------------


def make_narration(model, speaker):
    os.makedirs(NARRATION_DIR, exist_ok=True)
    for old in os.listdir(NARRATION_DIR):
        if old.endswith(".mp3") and old[:2].isdigit():
            os.remove(os.path.join(NARRATION_DIR, old))
    for seg in SEGMENTS:
        wav = os.path.join(BUILD_DIR, seg["id"] + ".wav")
        mp3 = os.path.join(NARRATION_DIR, seg["id"] + ".mp3")
        subprocess.run(["piper", "-m", model, "-f", wav, "-s", str(speaker)],
                       input=seg["text"], text=True, check=True, capture_output=True)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", wav,
                        "-codec:a", "libmp3lame", "-qscale:a", "2", mp3], check=True)
        print("Voice:", seg["id"])


def audio_seconds(path):
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                          "-of", "csv=p=0", path], capture_output=True, text=True, check=True).stdout
    return float(out.strip())


# ---------------------------------------------------------------------------
# Schnitt
# ---------------------------------------------------------------------------

PAD = 0.7  # short pause after each section


FIRST_HOLD, LAST_HOLD, PER_STEP_MIN = 1.2, 2.0, 0.5


def min_visual_seconds(n_frames):
    """Minimum duration so all steps of a terminal playback appear readably one after another
    and the final result still stays up - even if the narration is shorter."""
    if n_frames <= 2:
        return 0.0
    return FIRST_HOLD + PER_STEP_MIN * (n_frames - 2) + LAST_HOLD


def durations_for(n_frames, total):
    """Distributes the section duration over the individual images (sum == total, never negative)."""
    if n_frames == 1:
        return [total]
    per = (total - FIRST_HOLD - LAST_HOLD) / (n_frames - 2) if n_frames > 2 else 0
    mids = [per] * (n_frames - 2)
    last = LAST_HOLD if n_frames > 2 else total - FIRST_HOLD
    return [FIRST_HOLD] + mids + [last]


def build_segment(seg, frames, idx):
    mp3 = os.path.join(NARRATION_DIR, seg["id"] + ".mp3")
    if not os.path.exists(mp3):
        sys.exit(f"Missing: {mp3} - generate it first with --regen-narration.")
    total = max(audio_seconds(mp3) + PAD, min_visual_seconds(len(frames)))
    ds = durations_for(len(frames), total)
    assert all(d > 0 for d in ds) and abs(sum(ds) - total) < 1e-6, ds

    seg_dir = os.path.join(BUILD_DIR, f"seg_{idx:02d}")
    os.makedirs(seg_dir, exist_ok=True)
    listing = []
    for i, (im, dur) in enumerate(zip(frames, ds)):
        p = os.path.join(seg_dir, f"f{i:02d}.png")
        im.save(p)
        listing.append(f"file '{p}'\nduration {dur:.3f}")
    listing.append(f"file '{os.path.join(seg_dir, f'f{len(frames) - 1:02d}.png')}'")  # concat-Eigenheit
    lst = os.path.join(seg_dir, "list.txt")
    open(lst, "w").write("\n".join(listing) + "\n")

    out = os.path.join(BUILD_DIR, f"seg_{idx:02d}.mp4")
    vf = (f"fps=30,scale={W}:{H},fade=t=in:st=0:d=0.3,"
          f"fade=t=out:st={total - 0.3:.3f}:d=0.3,format=yuv420p")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst,
                    "-i", mp3, "-vf", vf, "-af", "apad", "-t", f"{total:.3f}",
                    "-c:v", "libx264", "-preset", "medium", "-crf", "20",
                    "-c:a", "aac", "-ar", "44100", "-ac", "2", "-b:a", "160k", out], check=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--regen-narration", action="store_true")
    ap.add_argument("--piper-model", default=None)
    ap.add_argument("--speaker", default="600")
    args = ap.parse_args()

    os.makedirs(BUILD_DIR, exist_ok=True)
    make_cards()
    if args.regen_narration:
        if not args.piper_model:
            sys.exit("--regen-narration braucht --piper-model PFAD/en-us-libritts-high.onnx")
        make_narration(args.piper_model, args.speaker)

    clips = []
    for idx, seg in enumerate(SEGMENTS, 1):
        kind, name = seg["visual"]
        if kind == "card":
            frames = [Image.open(os.path.join(CARD_DIR, name + ".png")).convert("RGB")]
        elif kind == "term":
            frames = terminal_frames(name)
        else:
            frames = viewer_frame()
        if seg.get("placeholder"):
            print("\n*** WARNING: section", seg["id"], "is still a PLACEHOLDER (Zetaris) - replace before submission! ***\n")
        clips.append(build_segment(seg, frames, idx))
        print("Section done:", seg["id"])

    lst = os.path.join(BUILD_DIR, "all.txt")
    open(lst, "w").write("".join(f"file '{c}'\n" for c in clips))
    final = os.path.join(BUILD_DIR, "demo.mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst,
                    "-c", "copy", "-movflags", "+faststart", final], check=True)
    print(f"\nDone: {final}  ({audio_seconds(final):.1f} s)")


if __name__ == "__main__":
    main()
