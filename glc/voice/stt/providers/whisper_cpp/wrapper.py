"""whisper.cpp wrapper shim.

Expects an absolute, explicitly-configured `whisper-cli` binary path
(GLC_WHISPER_CLI_PATH) and a base model at
~/.glc/models/whisper-base/ggml-base.bin. Invokes the binary as a
subprocess, parses the JSON output, returns (text, language,
duration_ms). The model download is handled by the install script.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

MODEL_DIR = Path(os.path.expanduser(os.getenv("GLC_WHISPER_MODEL_DIR", "~/.glc/models/whisper-base")))
MODEL_FILE = MODEL_DIR / "ggml-base.bin"

# L7 fix: resolve the binary from an explicit, absolute, configured path
# instead of searching the PATH environment variable for it. Searching
# PATH means whichever directory comes first and contains a file named
# whisper-cli wins — exploitable if any earlier-loaded, less-trusted
# code can write to a directory ahead of the real binary's location in
# PATH. Full closure (running this in a container with no other
# writable-then-executable paths ahead of it) is Move B territory; this
# closes the PATH-injection vector itself.
WHISPER_CLI_PATH = Path(os.getenv("GLC_WHISPER_CLI_PATH", "/usr/local/bin/whisper-cli"))

# No-speech threshold for whisper-cli; default speech-probability cut.
VAD_THRESHOLD = 0.6
# If every output segment reports no_speech_prob above this, the audio
# contains no speech (e.g. music-only) and we return an empty transcript.
NO_SPEECH_DISCARD = 0.7

# Performance tuning — override via env vars without code changes.
# Thread count: defaults to all logical CPUs; linear speedup up to ~8 cores.
_DEFAULT_THREADS = os.cpu_count() or 4
WHISPER_THREADS = int(os.getenv("GLC_WHISPER_THREADS", str(_DEFAULT_THREADS)))
# Beam size: 1=greedy (fastest), 5=default accuracy. 2 halves decoding cost
# with negligible accuracy loss on typical speech.
WHISPER_BEAM_SIZE = int(os.getenv("GLC_WHISPER_BEAM_SIZE", "2"))


def run_whisper_cpp(audio: bytes, mime: str, use_vad: bool = False) -> tuple[str, str, int]:
    if not WHISPER_CLI_PATH.is_file():
        raise RuntimeError(
            f"whisper-cli not found at {WHISPER_CLI_PATH} (set GLC_WHISPER_CLI_PATH). "
            "Install whisper.cpp and point GLC_WHISPER_CLI_PATH at its 'whisper-cli' "
            "binary, or use prefer='default' for Groq."
        )
    cli = str(WHISPER_CLI_PATH)
    if not MODEL_FILE.exists():
        raise RuntimeError(
            f"whisper base model not found at {MODEL_FILE}. Run "
            "`daemon/install.sh --models` or download manually."
        )
    suffix = ".wav" if "wav" in mime else ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(audio)
        audio_path = Path(f.name)
    try:
        cmd = [
            cli,
            "-m",
            str(MODEL_FILE),
            "-f",
            str(audio_path),
            "-oj",
            "-t",
            str(WHISPER_THREADS),  # use all cores → linear speedup
            "-bs",
            str(WHISPER_BEAM_SIZE),  # beam=2 ≈ 2× faster vs default 5
        ]
        # For long inputs, raise the no-speech threshold so whisper drops
        # no-speech segments more aggressively. `-nth` is model-free; the
        # native `--vad` flag would require a separate Silero VAD model.
        if use_vad:
            cmd.extend(["-nth", str(VAD_THRESHOLD)])

        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        audio_path.unlink(missing_ok=True)
    json_path = audio_path.with_suffix(audio_path.suffix + ".json")
    if json_path.exists():
        d = json.loads(json_path.read_text())
        json_path.unlink(missing_ok=True)
        segments = d.get("transcription") or d.get("segments") or []
        text = " ".join((s.get("text") or "").strip() for s in segments).strip()
        language = d.get("language") or "en"
        duration_ms = int(segments[-1].get("offsets", {}).get("to", 0)) if segments else 0
        # Music-only detection: when every segment is flagged as non-speech by
        # whisper's internal classifier, discard the (hallucinated) transcript.
        # Falls back safely to 0.0 when no_speech_prob is absent (older builds).
        if segments and all(s.get("no_speech_prob", 0.0) > NO_SPEECH_DISCARD for s in segments):
            return "", language, duration_ms
        return text, language, duration_ms
    return out.stdout.strip(), "en", 0
