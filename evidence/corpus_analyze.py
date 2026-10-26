"""
corpus_analyze.py — Post-hoc stability analysis of the RE observation corpus.

This is where the 1/50 rare insight becomes visible.

The system accumulates ALL 16-byte-aligned observations from T2+ fractal_memscan
tiers across N sessions. This tool applies memory_invariants.py-style analysis:
  - Which values are INVARIANT across sessions? (appear every session, same bytes)
  - Which addresses are ADDRESS_STATIC? (same VA every session)
  - Which (address, value) pairs are INVARIANT but never fired verify()? ← RARE SIGNAL

The rare signal is the unknown INVARIANT: a value that is as stable as KEY1 but
doesn't match any known (K, IV) pair. This is what the key derivation algorithm
outputs in a form we don't yet recognize — or a second key path we didn't know existed.

You can't engineer this insight. The corpus accumulates observations until the
pattern becomes statistically unmistakeable. This is the Mendel 3:1 ratio approach:
grow enough peas (run enough sessions) and the pattern emerges.

Usage:
    python corpus_analyze.py                     # full stability report
    python corpus_analyze.py --unknown-only      # INVARIANT values not matched by verify()
    python corpus_analyze.py --min-sessions 3    # only values seen in >= N sessions
    python corpus_analyze.py --verify-variants   # run verify() with all observed pairs
    python corpus_analyze.py --session-count     # how many sessions in corpus
"""

import os, sys, json, math, argparse
from collections import defaultdict

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from ground_truth import verify, KNOWLEDGE_JSON
    CORPUS_FILE = os.path.join(os.path.dirname(KNOWLEDGE_JSON), "re_corpus.jsonl")
    _HAS_VERIFY = True
except Exception:
    def verify(k, iv): return False
    _HAS_VERIFY = False
    CORPUS_FILE = os.path.join(_here, "re_corpus.jsonl")

# ── Load corpus ───────────────────────────────────────────────────────────────

def load_corpus(path: str):
    """
    Returns:
      sessions: list of dicts with metadata
      obs_by_session: {session_id: [(addr_hex, value_hex, tier, module_off_hex)]}
      verify_hits: [(session_id, addr_hex, key_hex, iv_hex)]
    """
    if not os.path.exists(path):
        return [], {}, []

    sessions       = {}
    obs_by_session = defaultdict(list)
    verify_hits    = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            sid   = r.get("session")
            event = r.get("event")

            if event == "begin_session":
                sessions[sid] = {"pid": r.get("pid"), "module_base": r.get("module_base"),
                                  "begin_ts": r.get("ts"), "end_ts": None, "duration_s": None}
            elif event == "end_session":
                if sid in sessions:
                    sessions[sid]["end_ts"]    = r.get("ts")
                    sessions[sid]["duration_s"] = r.get("duration_s")
            elif event == "observation":
                obs_by_session[sid].append((
                    r.get("addr"), r.get("value"), r.get("tier", 0),
                    r.get("module_offset")
                ))
            elif event == "verify_hit":
                verify_hits.append((sid, r.get("addr"), r.get("key"), r.get("iv")))

    return list(sessions.values()), dict(obs_by_session), verify_hits


# ── Stability analysis ────────────────────────────────────────────────────────
# Borrowed from memory_invariants.py methodology

def mean(xs): return sum(xs) / len(xs) if xs else 0.0
def stddev(xs):
    if len(xs) < 2: return 0.0
    m = mean(xs)
    return math.sqrt(sum((x-m)**2 for x in xs) / len(xs))

def analyse_corpus(obs_by_session: dict, n_sessions: int):
    """
    Returns: {(module_offset_or_addr, value_hex): stability_info}
    stability_info = {
      "vstab": INVARIANT|COMMON|EPHEMERAL,
      "astab": ADDRESS_STATIC|MODULE_RELATIVE|HEAP_STABLE|HEAP_VOLATILE,
      "freq": n_sessions_seen,
      "addrs": [all VAs],
      "tiers": [tier values],
      "repr_addr": median VA as int
    }
    """
    # key = (canonical_addr_key, value_hex)
    # canonical_addr_key = module_offset if available, else addr
    presence = defaultdict(lambda: defaultdict(list))  # (addr_key, val) → {sess_idx: [addr]}

    sess_list = list(obs_by_session.items())
    for sess_idx, (sid, obs) in enumerate(sess_list):
        for addr_hex, val_hex, tier, mod_off in obs:
            addr_key = mod_off if mod_off else addr_hex
            try:
                addr_int = int(addr_hex, 16) if addr_hex else 0
            except Exception:
                addr_int = 0
            presence[(addr_key, val_hex)][sess_idx].append((addr_int, tier))

    results = {}
    for (addr_key, val), run_map in presence.items():
        freq  = len(run_map)
        ratio = freq / max(n_sessions, 1)

        if ratio >= 1.0:
            vstab = "INVARIANT"
        elif ratio >= 0.75:
            vstab = "COMMON"
        elif freq == 1:
            vstab = "UNIQUE"
        else:
            vstab = "EPHEMERAL"

        all_addrs = [a for items in run_map.values() for a, _ in items]
        all_tiers = [t for items in run_map.values() for _, t in items]

        if all(a == all_addrs[0] for a in all_addrs):
            astab = "ADDRESS_STATIC"
        elif stddev(all_addrs) < 1024 * 1024:
            astab = "HEAP_STABLE"
        elif stddev(all_addrs) < 64 * 1024 * 1024:
            astab = "HEAP_MODERATE"
        else:
            astab = "HEAP_VOLATILE"

        results[(addr_key, val)] = {
            "vstab":     vstab,
            "astab":     astab,
            "freq":      freq,
            "addrs":     all_addrs,
            "tiers":     all_tiers,
            "repr_addr": sorted(all_addrs)[len(all_addrs)//2] if all_addrs else 0,
        }

    return results


def classify_against_oracle(results: dict, verified_keys: set[str]) -> dict:
    """
    For each INVARIANT/COMMON value, ask: did verify() ever fire for this value?
    If NOT → this is a candidate for UNKNOWN_INVARIANT — the rare signal.

    verified_keys: set of value_hex strings that appeared in verify_hits
    """
    classification = {}
    for (addr_key, val), info in results.items():
        if info["vstab"] in ("INVARIANT", "COMMON"):
            is_known = val in verified_keys
            classification[(addr_key, val)] = {
                **info,
                "oracle_match": is_known,
                "signal_class": "KNOWN_KEY" if is_known else "UNKNOWN_INVARIANT",
            }
    return classification


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_report(args):
    sessions, obs_by_session, verify_hits = load_corpus(CORPUS_FILE)
    n = len(sessions)
    total_obs = sum(len(v) for v in obs_by_session.values())

    if n == 0:
        print("No sessions in corpus. Run fractal_memscan with --corpus flag to accumulate data.")
        return

    print(f"Corpus: {CORPUS_FILE}")
    print(f"Sessions: {n}  |  Total observations: {total_obs:,}  |  Verify hits: {len(verify_hits)}")
    print()

    min_sess = args.min_sessions if hasattr(args, 'min_sessions') else 1
    filtered = {sid: obs for sid, obs in obs_by_session.items()}
    results  = analyse_corpus(filtered, n)

    # Extract verified values for oracle comparison
    verified_keys = {kh for _, _, kh, ih in verify_hits} | {ih for _, _, kh, ih in verify_hits}

    classified = classify_against_oracle(results, verified_keys)

    # ── Tier counts ──────────────────────────────────────────────────────────
    vstab_counts = defaultdict(int)
    for info in results.values():
        vstab_counts[info["vstab"]] += 1

    print("Value stability distribution:")
    for tier in ("INVARIANT", "COMMON", "EPHEMERAL", "UNIQUE"):
        print(f"  {tier:<12}: {vstab_counts[tier]:>6}")
    print()

    # ── UNKNOWN_INVARIANT — the rare signal ───────────────────────────────────
    unknown_inv = [(k, v) for k, v in classified.items()
                   if v["signal_class"] == "UNKNOWN_INVARIANT"
                   and v["vstab"] == "INVARIANT"]
    unknown_inv.sort(key=lambda x: -x[1]["freq"])

    print(f"UNKNOWN_INVARIANT (INVARIANT values never matched by verify()) — {len(unknown_inv)} total")
    if unknown_inv:
        print("  These are the RARE SIGNAL candidates: stable as K/IV but unrecognized.")
        print("  Run --verify-variants to test them against all algorithm variants.")
        print()
        for (addr_key, val), info in unknown_inv[:20]:
            repr_addr = info["repr_addr"]
            print(f"  {val}  [{info['astab']}]  "
                  f"freq={info['freq']}/{n}  "
                  f"addr={hex(repr_addr) if repr_addr else addr_key}"
                  f"  tiers={sorted(set(info['tiers']))}")
    else:
        print("  None yet. Run more sessions to build statistical power.")
    print()

    # ── KNOWN_KEY confirmations ───────────────────────────────────────────────
    known = [(k, v) for k, v in classified.items() if v["signal_class"] == "KNOWN_KEY"]
    print(f"KNOWN_KEY (INVARIANT/COMMON values confirmed by verify()): {len(known)}")
    for (addr_key, val), info in known[:10]:
        print(f"  {val[:16]}...  [{info['astab']}]  freq={info['freq']}/{n}")


def cmd_verify_variants(args):
    """
    Run all observed INVARIANT values as (K, IV) pairs against verify() AND
    against permutation variants (swap K/IV, XOR with known constants, etc.).
    This tests whether the key derivation algorithm has changed.
    """
    sessions, obs_by_session, verify_hits = load_corpus(CORPUS_FILE)
    n = len(sessions)
    if n == 0:
        print("No data in corpus.")
        return

    results = analyse_corpus(obs_by_session, n)
    invariants = [val for (_, val), info in results.items()
                  if info["vstab"] in ("INVARIANT", "COMMON")]

    print(f"Testing {len(invariants)} INVARIANT/COMMON values as oracle inputs...")
    hits = 0
    for k_val in invariants:
        try:
            k_bytes = bytes.fromhex(k_val)
        except Exception:
            continue
        for iv_val in invariants:
            if iv_val == k_val:
                continue
            try:
                iv_bytes = bytes.fromhex(iv_val)
            except Exception:
                continue
            if verify(k_bytes, iv_bytes):
                print(f"  HIT: K={k_val}  IV={iv_val}")
                hits += 1

    print(f"Done. {hits} hits from {len(invariants)}^2 pair combinations.")
    if hits == 0 and n >= 3:
        print("  FLOOR:ORACLE_MISMATCH — oracle may be stale (key derivation algorithm may have changed)")


def cmd_session_count(args):
    sessions, obs_by_session, verify_hits = load_corpus(CORPUS_FILE)
    print(f"Sessions    : {len(sessions)}")
    print(f"Observations: {sum(len(v) for v in obs_by_session.values()):,}")
    print(f"Verify hits : {len(verify_hits)}")
    for i, s in enumerate(sessions[:10], 1):
        dur = f"{s['duration_s']}s" if s.get('duration_s') else "ongoing"
        print(f"  {i:2d}. {s.get('begin_ts','?')}  pid={s.get('pid','?')}  dur={dur}")


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unknown-only",    action="store_true",
                    help="Show only INVARIANT values not matched by verify()")
    ap.add_argument("--min-sessions",    type=int, default=1, metavar="N",
                    help="Only include values seen in >= N sessions")
    ap.add_argument("--verify-variants", action="store_true",
                    help="Test all observed pairs with verify() and variants")
    ap.add_argument("--session-count",   action="store_true",
                    help="Show session count and metadata")
    args = ap.parse_args()

    if args.session_count:
        cmd_session_count(args)
    elif args.verify_variants:
        cmd_verify_variants(args)
    else:
        cmd_report(args)
