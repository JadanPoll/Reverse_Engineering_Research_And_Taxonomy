"""
structural/ghidra_run.py — PyGhidra headless structural extractor.

Runs structural/ghidra_dump_calltree.py against a target binary and writes calltree.json.
Validated 2026-05-26 (same invocation pattern as hss_toolkit/ghidra_run.py).

Usage:
  python -m structural.ghidra_run --calltree --binary foo.dll --proj-dir foo/ghidra_proj --out foo/calltree.json
  python -m structural.ghidra_run --sanity-only
"""

import subprocess, sys, os, argparse

try:
    from winreg import OpenKey, QueryValueEx, HKEY_CURRENT_USER
except ImportError:
    OpenKey = QueryValueEx = HKEY_CURRENT_USER = None

_here         = os.path.dirname(os.path.abspath(__file__))
GHIDRA_DIR    = os.environ.get("GHIDRA_DIR", "")
CALLTREE_SCRIPT = os.path.join(_here, "ghidra_dump_calltree.py")
SCRIPT_PATH   = _here


def get_java_home():
    val = os.environ.get("JAVA_HOME")
    if val:
        return val
    if OpenKey is not None:
        try:
            with OpenKey(HKEY_CURRENT_USER, r"Environment") as k:
                val, _ = QueryValueEx(k, "JAVA_HOME")
                return val
        except Exception:
            pass
    return None


def sanity_check():
    java_home = get_java_home()
    assert GHIDRA_DIR, "GHIDRA_DIR is not set"
    assert os.path.isdir(GHIDRA_DIR), f"GHIDRA_DIR does not exist: {GHIDRA_DIR}"
    assert java_home, "JAVA_HOME is not set"
    java_candidates = [
        os.path.join(java_home, "bin", "server", "jvm.dll"),
        os.path.join(java_home, "lib", "server", "libjvm.so"),
        os.path.join(java_home, "lib", "server", "libjvm.dylib"),
    ]
    jvm = next((p for p in java_candidates if os.path.isfile(p)), None)
    assert jvm, f"JVM library not found under JAVA_HOME: {java_home}"
    launch_props = os.path.join(GHIDRA_DIR, "support", "launch.properties")
    if os.path.isfile(launch_props):
        text = open(launch_props, encoding="utf-8", errors="replace").read()
        override = next(
            (line.split("=", 1)[1].strip()
             for line in text.splitlines()
             if line.startswith("JAVA_HOME_OVERRIDE=")),
            "",
        )
        if override:
            assert "${" not in override, \
                f"launch.properties has unexpanded JAVA_HOME_OVERRIDE={override!r}"
            assert os.path.isdir(override), \
                f"JAVA_HOME_OVERRIDE path does not exist: {override}"
            print(f"[OK] JAVA_HOME_OVERRIDE = {override}")
    print(f"[OK] JVM = {jvm}")
    print("[OK] Sanity checks passed")


def run_headless(proj_dir, proj_name, target_dll, script, reimport=False,
                 timeout_sec=600, extra_env=None):
    java_home = get_java_home()
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    if extra_env:
        env.update(extra_env)

    if reimport:
        action_args = ["-import", target_dll, "-overwrite",
                       "-analysisTimeoutPerFile", str(timeout_sec)]
    else:
        action_args = ["-process", os.path.basename(target_dll)]

    cmd = [
        sys.executable, "-m", "pyghidra.ghidra_launch",
        "--install-dir", GHIDRA_DIR,
        "ghidra.app.util.headless.AnalyzeHeadless",
        proj_dir, proj_name,
    ] + action_args + [
        "-postScript", script,
        "-scriptPath", SCRIPT_PATH,
    ]
    print(f"Running: {' '.join(cmd)}")
    return subprocess.call(cmd, env=env)


def main():
    p = argparse.ArgumentParser(description="PyGhidra headless calltree launcher")
    p.add_argument("--calltree", action="store_true",
                   help="Dump call tree + pseudocode via ghidra_dump_calltree.py")
    p.add_argument("--reimport", action="store_true",
                   help="Force re-import (overwrite existing project)")
    p.add_argument("--sanity-only", action="store_true",
                   help="Check Java/Ghidra config and exit")
    p.add_argument("--binary",   default=None,
                   help="Target binary path")
    p.add_argument("--proj-dir", default=None,
                   help="Ghidra project directory")
    p.add_argument("--out",      default=None,
                   help="Output calltree JSON path (sets GHIDRA_OUT env var)")
    p.add_argument("--gt-dir",   default=None,
                   help="Directory containing a legacy/test ground_truth.py fixture")
    p.add_argument("--seeds",    default=None,
                   help="Comma-separated hex VAs of seed functions (sets GHIDRA_SEEDS)")
    args = p.parse_args()

    sanity_check()
    if args.sanity_only:
        return

    if not args.calltree:
        p.error("Specify --calltree")

    proj = args.proj_dir
    dll  = args.binary
    assert proj and dll, "--proj-dir and --binary are required with --calltree"
    os.makedirs(proj, exist_ok=True)

    extra = {}
    if args.out:
        extra["GHIDRA_OUT"] = args.out
    if args.seeds:
        extra["GHIDRA_SEEDS"] = args.seeds
    elif args.gt_dir:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "test_gt", os.path.join(args.gt_dir, "ground_truth.py"))
        test_gt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(test_gt)
        vas = getattr(test_gt, "KNOWN_VAS", {})
        if vas:
            extra["GHIDRA_SEEDS"] = ",".join(hex(v) for v in vas.values())
            print(f"Seeds from test fixture: {extra['GHIDRA_SEEDS']}")
        out_default = getattr(test_gt, "CALLTREE_JSON", None)
        if out_default and not args.out:
            extra["GHIDRA_OUT"] = out_default

    run_headless(proj, "test_project", dll, CALLTREE_SCRIPT,
                 reimport=args.reimport, timeout_sec=600,
                 extra_env=extra or None)


if __name__ == "__main__":
    main()
