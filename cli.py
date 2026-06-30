"""
re_toolkit/cli.py — Single entry point for all toolkit operations.

USAGE:
    py -3.13 cli.py <command> [args]

COMMANDS:
    sweep               Classify all stripped test DLLs, print accuracy report
    sweep --filter X Y  Classify only test dirs X, Y
    classify <dll> <func>        Classify one function (export name or 0xVA)
    classify <dll> <func> --args N  Use N probe arguments (default 1)
    verify <module>     Run _verify() on a toolkit module
    kb                  Print knowledge base summary (verify_hits + observations)
    extract-vas         Patch ground_truth.py VAs for all test dirs
    calibrate           Measure machine-specific thresholds → dynamic/calibration.json
    constants           Print all constants with category and provenance

CRITICAL DISTINCTIONS (common LLM mistakes):
    --args 0  Use for test-wrapper exports (no inputs, return value is fixed)
    --args 1  Use for actual algorithm functions (vary arg[0], measure output)
    sweep uses --n-args 0 by default; classify uses --args 1 by default

    classify.run() takes executor=DLLExecutor(...), NOT dll_path=
    KNOWN_VAS in ground_truth.py are for the DEBUG dll, not _stripped.dll
    dynamic/runtime_probe.py ≠ runtime_probe.py (different files, different purpose)

EXAMPLES:
    py -3.13 cli.py sweep
    py -3.13 cli.py sweep --filter state_machines crc_checksum
    py -3.13 cli.py classify TESTS/prng_patterns/prng_patterns.dll xorshift_nonzero_test
    py -3.13 cli.py classify TESTS/prng_patterns/prng_patterns.dll 0x1d3d71470 --args 1
    py -3.13 cli.py verify classify
    py -3.13 cli.py verify knowledge_bus
    py -3.13 cli.py kb
    py -3.13 cli.py extract-vas
    py -3.13 cli.py calibrate
    py -3.13 cli.py constants
"""
import sys, os, argparse

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)


# ── command: sweep ─────────────────────────────────────────────────────────────

def cmd_sweep(args):
    import importlib.util, json as _json, datetime
    sweep_argv = []
    if args.filter:
        sweep_argv += ["--filter"] + args.filter
    if args.n_args:
        sweep_argv += ["--n-args", str(args.n_args)]

    # Capture sweep results for baseline comparison
    spec = importlib.util.spec_from_file_location(
        "sweep", os.path.join(_here, "dynamic", "sweep.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["sweep.py"] + sweep_argv
    spec.loader.exec_module(mod)

    # --save-baseline: persist accuracy for `cli.py health` regression check
    if args.save_baseline and hasattr(mod, "rows"):
        total   = len(mod.rows)
        correct = sum(1 for r in mod.rows if r.get("ok"))
        wrong   = total - correct
        acc     = correct / max(total, 1)
        baseline = {
            "date":     datetime.date.today().isoformat(),
            "accuracy": round(acc, 4),
            "total":    total,
            "correct":  correct,
            "wrong":    wrong,
        }
        path = os.path.join(_here, "dynamic", "sweep_baseline.json")
        with open(path, "w") as f:
            _json.dump(baseline, f, indent=2)
        print(f"\nBaseline saved: {acc:.1%} accuracy ({correct}/{total}) → {path}")


# ── command: classify ──────────────────────────────────────────────────────────

def cmd_classify(args):
    from dynamic.execute import DLLExecutor
    from dynamic.classify import run as classify_run
    import json

    ex   = DLLExecutor(args.dll)
    func = int(args.func, 16) if args.func.startswith("0x") else args.func
    code = ""
    if args.code:
        with open(args.code, encoding="utf-8", errors="replace") as f:
            code = f.read()

    result = classify_run(executor=ex, func=func, pseudocode=code,
                          n_args=args.n_args, bits=args.bits)

    if args.hint:
        print(result.llm_hint)
    elif args.synopsis:
        print(result.synopsis)
    else:
        d = {
            "func_id":      result.func_id,
            "func_class":   result.func_class,
            "confidence":   result.confidence,
            "primary_algo": result.primary_algo,
            "algo_score":   result.algo_score,
            "evidence":     result.evidence,
            "synopsis":     result.synopsis,
        }
        print(json.dumps(d, indent=2))
        print()
        print("LLM HINT:")
        print(result.llm_hint)


# ── command: verify ────────────────────────────────────────────────────────────

_VERIFY_MODULES = {
    "classify":      ("dynamic.classify",  "_verify"),
    "knowledge_bus": ("knowledge_bus",     "_verify"),
    "fingerprint":   ("dynamic.fingerprint", "_verify"),
    "execute":       ("dynamic.execute",   None),   # no _verify yet
    "pe_utils":      ("pe_utils",          "_verify"),
    "probe":         ("dynamic.probe",     None),
}

def _run_one_verify(name, mod_path, fn_name) -> bool:
    import importlib
    try:
        mod = importlib.import_module(mod_path)
        if fn_name is None or not hasattr(mod, fn_name):
            print(f"  {name:<20} SKIP (no _verify)")
            return True
        getattr(mod, fn_name)()
        print(f"  {name:<20} OK")
        return True
    except SystemExit:
        return True
    except Exception as e:
        print(f"  {name:<20} FAIL  {e}")
        return False


def cmd_verify(args):
    name = args.module
    if name not in _VERIFY_MODULES:
        print(f"Unknown module {name!r}. Available: {sorted(_VERIFY_MODULES)}")
        sys.exit(1)
    mod_path, fn_name = _VERIFY_MODULES[name]
    import importlib
    mod = importlib.import_module(mod_path)
    if fn_name is None or not hasattr(mod, fn_name):
        print(f"{name}: no _verify() implemented yet")
        return
    getattr(mod, fn_name)()


# ── command: kb ────────────────────────────────────────────────────────────────

def cmd_kb(args):
    from knowledge_bus import get_verify_hits, get_observations, _load
    data = _load()
    hits = get_verify_hits(min_stability="EPHEMERAL")
    obs  = get_observations(min_stability="EPHEMERAL")
    print(f"Knowledge base: {len(hits)} verify_hit(s), {len(obs)} observation(s)")
    if hits:
        print("\nVerify hits:")
        for h in hits:
            print(f"  [{h['stability']:<10}] K={h['key'][:8]}...  IV={h['iv'][:8]}..."
                  f"  layers={h['layers_seen']}  count={h['count']}")
    if obs:
        from collections import Counter
        types = Counter(o["obs_type"] for o in obs)
        print(f"\nObservations by type: {dict(types.most_common())}")
        for obs_type, n in types.most_common():
            stabilities = Counter(o["stability"] for o in obs if o["obs_type"] == obs_type)
            print(f"  {obs_type:<20} x{n}  {dict(stabilities)}")


# ── command: extract-vas ───────────────────────────────────────────────────────

def cmd_extract_vas(args):
    import subprocess
    result = subprocess.run(
        [sys.executable, os.path.join(_here, "TESTS", "_extract_vas.py")],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)


# ── command: graph-metrics ────────────────────────────────────────────────────

def _cmd_graph_metrics(args):
    import json, sys as _sys
    _sys.path.insert(0, os.path.join(_here, "dynamic"))
    from graph_metrics import annotate_calltree, print_ranked, print_components

    with open(args.path, encoding="utf-8") as f:
        data = json.load(f)
    fns = data["functions"]
    va_set = {fn["va"] for fn in fns}
    raw_seeds   = {v for v in data.get("function_seeds", []) if v and v != "0x0"}
    valid_seeds = raw_seeds & va_set
    seed_vas    = valid_seeds if valid_seeds else None

    extra = getattr(args, "extra_seeds", None)
    if extra:
        import os as _os
        if _os.path.isfile(extra):
            with open(extra, encoding="utf-8") as ef:
                extra_list = json.load(ef)
        else:
            extra_list = [v.strip() for v in extra.split(",") if v.strip()]
        extra_norm = set()
        for v in extra_list:
            try: extra_norm.add(hex(int(v, 16)))
            except ValueError: extra_norm.add(v)
        added = extra_norm & va_set
        seed_vas = (seed_vas or set()) | added
        print(f"[extra-seeds] +{len(added)} dynamic seeds injected")

    from graph_metrics import print_networkx_summary
    annotate_calltree(fns, seed_vas=seed_vas)
    if getattr(args, "nx", False):
        nx_sum = getattr(annotate_calltree, "_last_nx_summary", {})
        print_networkx_summary(nx_sum)
    if getattr(args, "components", False):
        comps = getattr(annotate_calltree, "_last_components", [])
        print_components(comps)
    print_ranked(fns, top_n=args.top)
    if args.annotate:
        with open(args.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\nAnnotated {len(fns)} functions → {args.path}")


# ── command: inspect-calltree / read-func ─────────────────────────────────────

def _cmd_inspect_calltree(args):
    import json
    with open(args.path, encoding="utf-8") as f:
        d = json.load(f)
    fns = d["functions"]
    CRT = ("__mingw_", "__gcc_", "_pei386_", "_register_", "DllMain",
           "tls_callback", "mark_section", "_FindPE", "_IsNon", "atexit",
           "_acrt", "_crt", "___", "__do_global", "_execute_", "_GetPE",
           "__main", "___chk", "__acrt")
    print(f"Program: {d['program']}  Functions: {d['count']}  Seeds: {d['function_seeds'][:3]}")
    print(f"{'SIZE':>6}  {'NAME':<42}  {'IN':>4}  {'OUT':>4}  {'PCODE':>6}  TAG")
    print("-" * 80)
    for fn in sorted(fns, key=lambda x: -x["size"]):
        is_crt = any(fn["name"].startswith(p) for p in CRT) or fn["name"] in (".text", "")
        tag = "CRT" if is_crt else "ALG"
        plen = len(fn.get("pseudocode") or "")
        print(f"{fn['size']:6d}  {fn['name']:<42}  {len(fn['calling_names']):4d}  "
              f"{len(fn['called_vas']):4d}  {plen:6d}  {tag}")


def _cmd_vtable_resolve(args):
    from dynamic.vtable_resolver import VTableResolver, KNOWN_CHAINS
    r = VTableResolver(args.dll, args.calltree)
    if args.detect:
        users = r.detect_vtable_users()
        print(f"Functions using vtable dispatch: {len(users)}")
        for name in users[:40]:
            print(f"  {name}")
        if len(users) > 40:
            print(f"  ... and {len(users)-40} more")
        return
    if getattr(args, "walk_chain", None):
        chain = KNOWN_CHAINS.get(args.walk_chain)
        if not chain:
            print(f"Unknown chain {args.walk_chain!r}. Available: {list(KNOWN_CHAINS)}")
            return
        all_results = r.walk_chain(chain, args.max_slots)
        total = 0
        for iface_name, slots in all_results.items():
            r.print_slots(iface_name, slots)
            if not args.no_kb:
                total += r.emit_to_kb(iface_name, slots)
        if not args.no_kb:
            print(f"\n[KB] emitted {total} vtable_slot observations total")
        return

    if getattr(args, "scan_section", None):
        fptrs = r.scan_section_for_fptrs(
            section_name=args.scan_section,
            call_before=getattr(args, "init_export", None),
        )
        r.print_section_fptrs(fptrs)
        if not args.no_kb and fptrs:
            n = r.emit_to_kb(f"section:{args.scan_section}", fptrs)
            print(f"\n[KB] emitted {n} vtable_slot observations")
        return
    if not args.export:
        print("ERROR: --export required (unless --detect or --walk-chain)")
        return
    if not args.iid:
        print("ERROR: --iid required for COM factory resolution")
        return
    slots = r.call_com_factory(args.export, args.iid, args.max_slots)
    r.print_slots(args.name, slots)
    if not args.no_kb:
        n = r.emit_to_kb(args.name, slots)
        print(f"\n[KB] emitted {n} vtable_slot observations (layer=vtable)")


def _cmd_read_func(args):
    import json
    with open(args.path, encoding="utf-8") as f:
        d = json.load(f)
    for fn in d["functions"]:
        if fn["name"] == args.name or fn["va"] == args.name:
            print(f"=== {fn['name']} @ {fn['va']}  size={fn['size']} ===")
            print(f"callers: {fn['calling_names']}")
            print(f"callees: {fn['named_callees']}")
            print()
            print(fn.get("pseudocode") or "(no pseudocode)")
            return
    print(f"Function {args.name!r} not found in {args.path}")


# ── command: health ───────────────────────────────────────────────────────────

def cmd_health(args):
    """Run _verify() on every module and print pass/fail. Target: < 10s total."""
    import datetime, json as _json
    print(f"re_toolkit health check  ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M')})\n")
    passed = failed = skipped = 0
    for name, (mod_path, fn_name) in sorted(_VERIFY_MODULES.items()):
        ok = _run_one_verify(name, mod_path, fn_name)
        if ok:
            passed += 1
        else:
            failed += 1

    # Sweep baseline comparison
    baseline_path = os.path.join(_here, "dynamic", "sweep_baseline.json")
    if os.path.exists(baseline_path):
        with open(baseline_path) as f:
            baseline = _json.load(f)
        print(f"\nSweep baseline ({baseline['date']}): {baseline['accuracy']:.1%} accuracy, "
              f"{baseline['total']} functions, {baseline['wrong']} wrong")
        print("  Run `cli.py sweep` to check for regressions.")
    else:
        print("\nNo sweep baseline stored. Run `cli.py sweep --save-baseline` to create one.")

    print(f"\n{'OK' if failed == 0 else 'FAIL'}  {passed} passed  {failed} failed")
    if failed:
        sys.exit(1)


# ── command: memory-observe ───────────────────────────────────────────────────

def cmd_memory_observe(args):
    """Run MemoryObserver on one function. Run BEFORE other calls to keep state fresh."""
    from dynamic.execute import DLLExecutor
    from dynamic.memory_observer import MemoryObserver
    import json

    ex   = DLLExecutor(args.dll)
    func = int(args.func, 16) if args.func.startswith("0x") else args.func
    obs  = MemoryObserver(ex)

    print(f"Writable sections: {[s['name'] for s in obs._sections]}")
    print(f"Observing {args.func} × {args.n} calls...")

    transitions = obs.observe(func, n_calls=args.n)
    hint = obs.llm_hint(str(func), transitions, n_calls=args.n)
    print()
    print(hint)

    if transitions:
        print(f"\n{len(transitions)} address(es) changed:")
        for t in transitions:
            print(json.dumps(t.to_dict(), indent=2))

    if args.emit and transitions:
        obs.emit_to_kb(str(func), transitions)
        n_inv = sum(1 for t in transitions if t.consistent)
        print(f"\nEmitted {n_inv} invariant(s) to KB.")


# ── command: calibrate ────────────────────────────────────────────────────────

def cmd_calibrate(args):
    """
    Measure machine-specific thresholds and write to dynamic/calibration.json.

    Runs micro-benchmarks to find the timing noise floor, then sets
    STATEFUL_TIMING_CV_THRESHOLD = noise_floor * 3 (3× gives safe separation
    between genuine constant functions and fast stateful ones).

    Also measures IPSampler's effective sample rate on this machine.
    """
    import ctypes, time, statistics, math
    from dynamic.constants import write_calibration, GUARD_PAGE_SIZE

    print("Calibrating machine-specific thresholds...")

    # ── 1. Timing noise floor: call a known-constant trivial function 2000 times
    # We synthesize one in memory rather than requiring a DLL.
    # x64 machine code: mov eax, 42 ; ret
    SHELLCODE = bytes([0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
    MEM_COMMIT   = 0x1000
    MEM_RESERVE  = 0x2000
    PAGE_EXEC_RW = 0x40

    k32 = ctypes.WinDLL("kernel32") if sys.platform == "win32" else None
    calibrated = {}

    if k32:
        k32.VirtualAlloc.restype  = ctypes.c_void_p
        k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.c_ulong, ctypes.c_ulong]
        k32.VirtualFree.restype   = ctypes.c_bool
        k32.VirtualFree.argtypes  = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        buf = k32.VirtualAlloc(None, GUARD_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXEC_RW)
        if buf:
            ctypes.memmove(buf, SHELLCODE, len(SHELLCODE))
            fn = ctypes.CFUNCTYPE(ctypes.c_int32)(buf)

            timings = []
            for _ in range(2000):
                t0 = time.perf_counter()
                fn()
                timings.append((time.perf_counter() - t0) * 1e6)

            k32.VirtualFree(buf, 0, 0x8000)

            # Drop warmup (first 200) and outliers (top 1%)
            timings = sorted(timings[200:])
            timings = timings[:int(len(timings) * 0.99)]
            mean = statistics.mean(timings)
            std  = statistics.stdev(timings)
            noise_cv = std / mean if mean > 0 else 0.05

            # NOTE: do NOT calibrate STATEFUL_TIMING_CV_THRESHOLD from shellcode.
            # At sub-microsecond timescales, perf_counter jitter dominates the cv
            # measurement and produces unreliable results. The 0.15 value was measured
            # empirically against 111 real DLL functions (2026-06-19, 93.7% accuracy)
            # and is more reliable than a micro-benchmark. Print informational only.
            print(f"  Constant-function timing: mean={mean:.2f}µs  std={std:.2f}µs  cv={noise_cv:.4f}")
            print(f"  NOTE: STATEFUL_TIMING_CV_THRESHOLD NOT updated (shellcode timescale too fine;")
            print(f"        empirical sweep value 0.15 is more reliable — re-sweep to recalibrate)")
        else:
            print("  VirtualAlloc failed — skipping timing noise measurement")
    else:
        print("  Non-Windows — timing calibration skipped")

    # ── 2. Thread suspend latency estimate (for IPSampler interval)
    # Measure GetThreadContext call latency — this IS machine-dependent and safe to calibrate.
    if k32 and sys.platform == "win32":
        k32.GetCurrentThread.restype  = ctypes.c_size_t   # pseudo-handle, use size_t not void_p
        k32.GetThreadContext.restype  = ctypes.c_bool
        k32.GetThreadContext.argtypes = [ctypes.c_size_t, ctypes.c_void_p]
        th = k32.GetCurrentThread()
        CONTEXT_CONTROL = 0x1
        # CONTEXT struct for x64 is 1232 bytes; we only need ContextFlags field
        ctx_buf = (ctypes.c_ubyte * 1232)()
        ctypes.cast(ctx_buf, ctypes.POINTER(ctypes.c_ulong))[0] = CONTEXT_CONTROL
        t0 = time.perf_counter()
        ok = 0
        for _ in range(500):
            if k32.GetThreadContext(th, ctypes.byref(ctx_buf)):
                ok += 1
        gtc_us = (time.perf_counter() - t0) * 1e6 / 500
        # IPSampler interval should be >= 3× GetThreadContext latency to not dominate execution
        interval = round(max(5.0, min(50.0, gtc_us * 3)), 1)
        calibrated["ipsampler_interval_us"] = interval
        print(f"  GetThreadContext latency: {gtc_us:.1f}µs ({ok}/500 succeeded)"
              f"  → IPSAMPLER_INTERVAL_US → {interval}µs")

    if calibrated:
        write_calibration(calibrated)
        print(f"\nRun `py -3.13 cli.py verify classify` to confirm thresholds are still correct.")
    else:
        print("Nothing calibrated.")


# ── entry point ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="re_toolkit CLI — single entry point for all toolkit operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="command", required=True)

    # health
    sub.add_parser("health", help="Run _verify() on all modules + check sweep baseline")

    # memory-observe
    p_mo = sub.add_parser("memory-observe", help="Observe global state changes caused by a function")
    p_mo.add_argument("dll",  help="Path to DLL")
    p_mo.add_argument("func", help="Export name or 0xVA")
    p_mo.add_argument("--n",   type=int, default=10, help="Number of calls (default 10)")
    p_mo.add_argument("--emit", action="store_true", help="Emit invariants to knowledge_bus")

    # sweep
    p_sweep = sub.add_parser("sweep", help="Classify all stripped test DLLs")
    p_sweep.add_argument("--filter", nargs="*", metavar="DIR",
                         help="Only run these test dirs")
    p_sweep.add_argument("--n-args", type=int, default=0, dest="n_args",
                         help="Probe argument count (default 0)")
    p_sweep.add_argument("--save-baseline", action="store_true",
                         help="Save accuracy as regression baseline for `cli.py health`")

    # classify
    p_cls = sub.add_parser("classify", help="Classify one function")
    p_cls.add_argument("dll",  help="Path to DLL")
    p_cls.add_argument("func", help="Export name or Ghidra VA (0x...)")
    p_cls.add_argument("--args",     type=int, default=1, dest="n_args",
                       help="Number of probe arguments (default 1)")
    p_cls.add_argument("--bits",     type=int, default=64)
    p_cls.add_argument("--code",     default="", help="Pseudocode file")
    p_cls.add_argument("--hint",     action="store_true", help="Print only llm_hint")
    p_cls.add_argument("--synopsis", action="store_true", help="Print only synopsis")

    # verify
    p_ver = sub.add_parser("verify", help="Run _verify() on a module")
    p_ver.add_argument("module", choices=sorted(_VERIFY_MODULES),
                       help="Module to verify")

    # kb
    sub.add_parser("kb", help="Print knowledge base summary")

    # extract-vas
    sub.add_parser("extract-vas", help="Patch ground_truth.py VAs for all test dirs")

    # graph-metrics
    p_gm = sub.add_parser("graph-metrics", help="Compute k-core + betweenness for a calltree JSON")
    p_gm.add_argument("path", help="Path to calltree.json")
    p_gm.add_argument("--top", type=int, default=0, help="Show top N by graph_rank")
    p_gm.add_argument("--annotate", action="store_true", help="Write metrics back into JSON")
    p_gm.add_argument("--extra-seeds", metavar="VAs", dest="extra_seeds",
                      help="Comma-separated hex VAs or path to JSON list — runtime-discovered seeds")
    p_gm.add_argument("--components", action="store_true",
                      help="Show WCC component analysis (density, clustering, role)")
    p_gm.add_argument("--nx", action="store_true",
                      help="Show NetworkX metrics: SCC, PageRank, degree entropy, power-law")

    # inspect-calltree
    p_ict = sub.add_parser("inspect-calltree", help="Show function complexity breakdown for a calltree JSON")
    p_ict.add_argument("path", help="Path to calltree.json")

    # read-func
    p_rf = sub.add_parser("read-func", help="Print full pseudocode for one function from a calltree")
    p_rf.add_argument("path", help="Path to calltree.json")
    p_rf.add_argument("name", help="Function name or VA (0x...)")

    # calibrate
    sub.add_parser("calibrate", help="Measure machine-specific thresholds -> calibration.json")

    # constants
    sub.add_parser("constants", help="Print all constants with provenance")

    # vtable-resolve
    p_vr = sub.add_parser("vtable-resolve", help="Dynamic COM vtable resolution via object inspection")
    p_vr.add_argument("calltree", help="Path to calltree.json")
    p_vr.add_argument("dll",      help="Path to DLL")
    p_vr.add_argument("--export", help="Factory export name (HRESULT factory(REFIID, void**))")
    p_vr.add_argument("--iid",    help='Interface IID e.g. "{7b7166ec-21c7-44ae-b21a-c9ae321ae369}"')
    p_vr.add_argument("--name",   default="Interface", help="Interface name label")
    p_vr.add_argument("--max-slots", type=int, default=64, dest="max_slots")
    p_vr.add_argument("--detect",       action="store_true", help="List functions using vtable dispatch")
    p_vr.add_argument("--walk-chain",   metavar="CHAIN", dest="walk_chain",
                      help="Walk a built-in chain spec (e.g. dxgi)")
    p_vr.add_argument("--scan-section", metavar="NAME", dest="scan_section",
                      help="Scan a section for runtime fn ptrs (e.g. .data)")
    p_vr.add_argument("--init-export",  metavar="FN",   dest="init_export",
                      help="Call this export before scanning (e.g. retro_init)")
    p_vr.add_argument("--no-kb",        action="store_true", dest="no_kb")

    # struct-recover
    p_sr = sub.add_parser("struct-recover",
                          help="Program geometry analysis: recover struct layout from global co-access patterns")
    p_sr.add_argument("dll",      help="Path to DLL")
    p_sr.add_argument("calltree", help="Path to calltree.json")
    p_sr.add_argument("--gap",    type=lambda x: int(x,0), default=0x1000,
                      dest="gap", help="Proximity gap threshold in bytes (default 0x1000)")
    p_sr.add_argument("--max-fns", type=int, default=None, dest="max_fns",
                      help="Max functions to probe")
    p_sr.add_argument("--emit-kb", action="store_true", dest="emit_kb",
                      help="Emit discovered struct fields to knowledge bus")
    p_sr.add_argument("--verbose", action="store_true")

    args = ap.parse_args()
    {
        "graph-metrics":    lambda a: _cmd_graph_metrics(a),
        "struct-recover":   lambda a: _cmd_struct_recover(a),
        "inspect-calltree": lambda a: _cmd_inspect_calltree(a),
        "read-func":        lambda a: _cmd_read_func(a),
        "vtable-resolve":   lambda a: _cmd_vtable_resolve(a),
        "health":         cmd_health,
        "sweep":          cmd_sweep,
        "classify":       cmd_classify,
        "verify":         cmd_verify,
        "memory-observe": cmd_memory_observe,
        "kb":             cmd_kb,
        "extract-vas":    cmd_extract_vas,
        "calibrate":      cmd_calibrate,
        "constants":      lambda _: __import__("dynamic.constants", fromlist=["print_summary"]).print_summary(),
    }[args.command](args)


def _cmd_struct_recover(args):
    """Program geometry analysis — recover struct layout from global co-access patterns.

    Computes projections T1-T5, P6-P9 across all functions with global reads,
    then clusters globals into candidate structs and classifies them:
      STRUCT (T3>80%): C struct with 4B-aligned fields
      LOOKUP_TABLE (T3<40%): dense byte/short table or dispatch table
      ENUM_FLAGS (40-80%): mixed-size flags/enums
    """
    import re, ctypes, sys, time
    from dynamic.pcode_sym import PCODESymEx
    from dynamic.execute import DLLExecutor
    from dynamic.struct_recover import ProgramGeometry, print_report
    from pe_utils import PE
    import json

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    pe = PE(args.dll)
    executor = DLLExecutor(args.dll)
    rebase = executor.load_base - pe.image_base
    _WRITE = 0x80000000
    global_ranges = [
        (pe.image_base + s['vrva'], pe.image_base + s['vrva'] + s['vsize'])
        for s in pe.sections if s['vsize'] > 0 and (s['chars'] & _WRITE)
    ]

    with open(args.calltree, encoding='utf-8') as f:
        all_fns = json.load(f)['functions']

    fns = [fn for fn in all_fns
           if re.search(r'DAT_[0-9a-fA-F]+', fn.get('pseudocode', '') or '')]
    if args.max_fns:
        fns = fns[:args.max_fns]

    label = args.dll.replace('\\', '/').split('/')[-1]
    pg = ProgramGeometry(label, gap_threshold=args.gap,
                         emit_to_kb=getattr(args, 'emit_kb', False))

    t0 = time.perf_counter()
    for i, fn in enumerate(fns):
        va = int(fn['va'], 16)
        size = fn['size']
        if size < 4 or size > 8000:
            continue
        if args.verbose and i % 50 == 0:
            print(f'  {i}/{len(fns)}...', file=sys.stderr, flush=True)
        try:
            code = bytes((ctypes.c_uint8 * size).from_address(va + rebase))
            exe = PCODESymEx('x86:LE:64:default', code, va,
                             global_ranges=global_ranges, verbose=False)
            r = exe.run(va, initial_regs={'RSP': 0x7FF00000, 'RCX': 0x1000},
                        max_steps=5000, wall_timeout=6.0)
            if r.global_reads or r.struct_field_reads:
                pg.add_function(fn['name'], r.global_reads,
                                first_access_steps=r.global_first_step or None,
                                struct_field_reads=r.struct_field_reads or None)
        except Exception:
            pass

    report = pg.analyze()
    print_report(report, verbose=args.verbose)
    print(f'\n({time.perf_counter()-t0:.0f}s, {len(pg._fn_globals)} fns with globals)')


if __name__ == "__main__":
    main()
