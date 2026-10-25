# Rebuild the video (12 scenes, starts with a 15-second intro, follows the 13 slides)

In the project folder, with the venv activated (as for the measurements):

1. Generate the voice (needs internet, engine edge):
   `python3 video/make_voices.py --engine edge --voice en-GB-RyanNeural`
   (To test first: `python3 video/make_voices.py --preview "This is a test."`)
2. Build the video (runs main.py in a throwaway copy, your logs/ folder stays untouched):
   `python3 video/make_video.py`
   With AI instead of example mode (takes longer, Ollama must be running):
   `VIDEO_TRACE_PROVIDER=ollama python3 video/make_video.py`
3. Result: `video/build/demo.mp4`. Check: length <= 4:00, terminal scenes readable.

Scene 08 (Zetaris) is now a fact card from the real live run. Optional: instead of the card, use a real screen recording of `python3 main.py --case CVE-2021-44228 --source zetaris`.
Important: after a change, re-record the texts (`python3 video/make_voices.py --engine edge --voice en-GB-RyanNeural`), then `python3 video/make_video.py`. Check the length (< 4:00).
If a terminal scene aborts with "too long" or "section missing": send me the error message.
