#!/usr/bin/env python3
"""
Generates the narration files (narration/*.mp3) with the engine of your choice.
Then rebuild the video:  python3 video/make_video.py

Engines (from mostly most natural to simplest):
  edge    Microsoft's neural voices via the online service. Needs internet.
          pip install edge-tts
  kokoro  local model, no online service, Apache-2.0.
          pip install kokoro soundfile   +   sudo apt install espeak-ng
  piper   local, simpler, but audibly more artificial.
          pip install piper-tts   +   --voice PATH/model.onnx

Examples:
  python3 video/make_voices.py --preview "This is a test."          # one sample, engine edge
  python3 video/make_voices.py --engine edge --voice en-US-GuyNeural
  python3 video/make_voices.py --engine kokoro --voice am_adam
  python3 video/make_voices.py --engine edge --only 07              # only redo section 07
  python3 video/make_voices.py --list-voices                        # list Edge voices

Note: edge and kokoro I could NOT run in my own environment
(the required internet addresses are blocked there) - only the piper path is tested.
"""

import argparse
import asyncio
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NARRATION_DIR = os.path.join(ROOT, "narration")
sys.path.insert(0, HERE)

from script import SEGMENTS  # noqa: E402

DEFAULT_VOICE = {"edge": "en-US-AndrewNeural", "kokoro": "am_adam", "piper": None}


def to_mp3(src, dst):
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", src,
                    "-codec:a", "libmp3lame", "-qscale:a", "2", dst], check=True)


# --- Engines -----------------------------------------------------------------

def tts_edge(text, voice, out_mp3, args):
    import edge_tts

    async def run():
        await edge_tts.Communicate(text, voice, rate=args.rate).save(out_mp3)

    asyncio.run(run())


_kokoro = {}


def tts_kokoro(text, voice, out_mp3, args):
    import numpy as np
    import soundfile as sf
    from kokoro import KPipeline

    lang = voice[0]  # 'a' = American, 'b' = British (prefix of the voice ID)
    if lang not in _kokoro:
        _kokoro[lang] = KPipeline(lang_code=lang)
    parts = []
    for _, _, audio in _kokoro[lang](text, voice=voice, speed=args.speed):
        parts.append(audio.numpy() if hasattr(audio, "numpy") else np.asarray(audio))
    with tempfile.TemporaryDirectory() as tmp:
        wav = os.path.join(tmp, "k.wav")
        sf.write(wav, np.concatenate(parts), 24000)
        to_mp3(wav, out_mp3)


def tts_piper(text, voice, out_mp3, args):
    if not voice or not os.path.exists(voice):
        sys.exit("piper needs --voice PATH/to/voice.onnx")
    cmd = ["piper", "-m", voice, "-f", None]
    if args.speaker is not None:
        cmd += ["-s", str(args.speaker)]
    with tempfile.TemporaryDirectory() as tmp:
        wav = os.path.join(tmp, "p.wav")
        cmd[cmd.index(None)] = wav
        subprocess.run(cmd, input=text, text=True, check=True, capture_output=True)
        to_mp3(wav, out_mp3)


ENGINES = {"edge": tts_edge, "kokoro": tts_kokoro, "piper": tts_piper}
HINTS = {
    "edge": "pip install edge-tts   (and an internet connection)",
    "kokoro": "pip install kokoro soundfile   und   sudo apt install espeak-ng",
    "piper": "pip install piper-tts",
}


def list_edge_voices():
    import edge_tts
    voices = asyncio.run(edge_tts.list_voices())
    for v in sorted(voices, key=lambda x: x["ShortName"]):
        if v["Locale"].startswith("en-"):
            print(f"{v['ShortName']:28} {v['Gender']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", choices=ENGINES, default="edge")
    ap.add_argument("--voice", default=None)
    ap.add_argument("--rate", default="+0%", help="edge: speed, e.g. -10%% (slower) or +5%%")
    ap.add_argument("--speed", type=float, default=1.0, help="kokoro: speed, 1.0 = normal")
    ap.add_argument("--speaker", type=int, default=None, help="piper: speaker number (multi-speaker models)")
    ap.add_argument("--only", default=None, help="only sections whose ID contains this piece, e.g. 07")
    ap.add_argument("--preview", default=None, metavar="TEXT", help="speak only this text -> narration/_preview.mp3")
    ap.add_argument("--list-voices", action="store_true", help="list English Edge voices")
    args = ap.parse_args()

    if args.list_voices:
        list_edge_voices()
        return

    voice = args.voice or DEFAULT_VOICE[args.engine]
    fn = ENGINES[args.engine]
    os.makedirs(NARRATION_DIR, exist_ok=True)

    jobs = ([("_preview", args.preview)] if args.preview else
            [(s["id"], s["text"]) for s in SEGMENTS if not args.only or args.only in s["id"]])
    if not jobs:
        sys.exit(f"No section matches --only {args.only!r}")

    for name, text in jobs:
        out = os.path.join(NARRATION_DIR, name + ".mp3")
        tmp_out = out + ".tmp.mp3"  # write here first: a failure must never
        try:                         # destroy an existing, working file
            fn(text, voice, tmp_out, args)
            if not os.path.exists(tmp_out) or os.path.getsize(tmp_out) == 0:
                raise RuntimeError("the engine returned no audio data")
            os.replace(tmp_out, out)
        except ImportError as e:
            _cleanup(tmp_out)
            sys.exit(f"For --engine {args.engine} a library is missing ({e.name}). Install: {HINTS[args.engine]}")
        except Exception as e:  # network, wrong voice ID, ...
            _cleanup(tmp_out)
            sys.exit(f"Error with engine '{args.engine}', voice '{voice}': {type(e).__name__}: {e}")
        print(f"ok: {out}")


def _cleanup(path):
    if os.path.exists(path):
        os.remove(path)


if __name__ == "__main__":
    main()
