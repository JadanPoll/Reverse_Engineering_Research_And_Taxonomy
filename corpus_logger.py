"""
corpus_logger.py — Rolling corpus of ALL 16-byte-aligned observations from T2+ tiers.

The system is built to confirm known hypotheses (verify() fires when K+IV match).
The 1/50 rare insight lives in the GAP: INVARIANT values that don't match any
known pattern — bytes that appear every session at the same module-relative address
but aren't K or IV. You can't reason your way to these. The corpus accumulates them
until the pattern becomes unmistakeable.

Contrast with verify():
  verify() = point query: "does this (K, IV) match?"
  corpus   = distributional query: "what is stable at this address across N sessions?"

The rare signal is an INVARIANT value in the corpus that verify() never fires on.
That's the thing you couldn't engineer — only observe.

Usage (called by fractal_memscan.py on T2+ observations):
    from corpus_logger import log_observation, begin_session, end_session

Post-hoc analysis:
    python corpus_analyze.py                    # stability analysis across all sessions
    python corpus_analyze.py --min-sessions 3   # only values seen in 3+ sessions
    python corpus_analyze.py --unknown-only     # INVARIANT values that don't match verify()

Schema (JSONL, one entry per observation batch):
    {"session": "uuid", "ts": "ISO", "event": "begin_session", "pid": N}
    {"session": "uuid", "ts": "ISO", "event": "observation",
     "addr": "0x...", "module_offset": "0x...", "value": "hex16", "tier": N}
    {"session": "uuid", "ts": "ISO", "event": "end_session", "duration_s": N}
"""

import os, sys, json, uuid, datetime, threading

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

try:
    from ground_truth import KNOWLEDGE_JSON
    CORPUS_FILE = os.path.join(os.path.dirname(KNOWLEDGE_JSON), "re_corpus.jsonl")
except Exception:
    CORPUS_FILE = os.path.join(_here, "re_corpus.jsonl")

_session_id   = None
_session_start = None
_module_base   = 0
_lock = threading.Lock()

# ── Public API ────────────────────────────────────────────────────────────────

def begin_session(pid: int, module_base: int = 0):
    global _session_id, _session_start, _module_base
    _session_id    = str(uuid.uuid4())[:8]
    _session_start = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    _module_base   = module_base
    _write({"event": "begin_session", "pid": pid, "module_base": hex(module_base) if module_base else None})
    return _session_id


def end_session():
    if _session_id and _session_start:
        dur = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - _session_start).total_seconds()
        _write({"event": "end_session", "duration_s": round(dur, 1)})


def log_observation(addr: int, value: bytes, tier: int, context: str = ""):
    """
    Log a 16-byte observation from a T2+ tier scan.
    Called for EVERY interesting 16-byte block, not just verify() hits.
    The rare signal lives in the blocks that never fire verify().

    addr:    virtual address where bytes were observed
    value:   exactly 16 bytes
    tier:    fractal_memscan tier level (2=hot, 3=burn, 4=live)
    context: optional label (e.g. "bcrypt_output", "stack_frame")
    """
    if not _session_id:
        return
    if len(value) != 16 or value == b'\x00' * 16:
        return

    module_off = (addr - _module_base) if _module_base else None
    entry = {
        "event":         "observation",
        "addr":          hex(addr),
        "value":         value.hex(),
        "tier":          tier,
    }
    if module_off is not None and 0 < module_off < 0x40000000:
        entry["module_offset"] = hex(module_off)
    if context:
        entry["context"] = context
    _write(entry)


def log_verify_hit(addr: int, key: bytes, iv: bytes, layer: str):
    """Record a verify() success — tagged so post-hoc analysis can filter it out
    and focus on the UNKNOWN INVARIANT values nearby."""
    if not _session_id:
        return
    _write({
        "event":  "verify_hit",
        "addr":   hex(addr),
        "key":    key.hex(),
        "iv":     iv.hex(),
        "layer":  layer,
    })


# ── Internal ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _write(payload: dict):
    if not _session_id:
        return
    record = {"session": _session_id, "ts": _now(), **payload}
    line   = json.dumps(record, separators=(",", ":"))
    with _lock:
        with open(CORPUS_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


# ── Self-test ──────────────────────────────────────────────────────────────────

def _verify():
    import tempfile, os as _os

    global CORPUS_FILE
    orig = CORPUS_FILE
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as tmp:
        CORPUS_FILE = tmp.name

    try:
        sid = begin_session(pid=9999, module_base=0x180000000)
        assert sid is not None

        # POSITIVE: non-null 16-byte block is logged
        log_observation(0x182a2d830, bytes(range(16)), tier=2)
        # NEGATIVE: null block is not logged
        log_observation(0x182a2d840, b'\x00' * 16, tier=2)
        # POSITIVE: verify hit is logged with event=verify_hit
        log_verify_hit(0x182a2d830, bytes(range(16)), bytes(range(16, 32)), "memscan")

        end_session()

        with open(CORPUS_FILE) as f:
            lines = [json.loads(l) for l in f]

        events = [l["event"] for l in lines]
        assert events[0] == "begin_session"
        assert "observation" in events
        assert "verify_hit" in events
        assert "end_session" in events

        # NEGATIVE: null block must not be logged
        obs_values = [l["value"] for l in lines if l["event"] == "observation"]
        assert "00000000000000000000000000000000" not in obs_values

        # POSITIVE: module_offset is computed for in-range addresses
        obs = next(l for l in lines if l["event"] == "observation")
        assert "module_offset" in obs

        print("OK: corpus_logger.py verified")
        print(f"  {len(lines)} records: {dict((e, events.count(e)) for e in set(events))}")

    finally:
        CORPUS_FILE = orig
        _os.unlink(tmp.name)


if __name__ == "__main__":
    _verify()
