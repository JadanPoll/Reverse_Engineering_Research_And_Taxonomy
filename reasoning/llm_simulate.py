"""
llm_simulate.py — Ask Claude to trace/simulate a decompiled function with
                  concrete input values, revealing branch decisions and routing.

This is concrete tracing: the LLM reads pseudocode, substitutes provided
values for inputs and named callee return values, and traces execution
step-by-step — showing which branches are taken and why.

Useful for:
  - Understanding branch/routing decisions for specific inputs
  - Verifying crypto algorithm hypotheses (e.g. "does MD5(MachineGuid) = T1EE1...?")
  - Inverse analysis: "what input produces output X?"
  - AES key derivation path tracing with known constants

Usage:
    python llm_simulate.py --va 0x181eXXXX
        [--calltree ghidra_calltree.json]
        [--names   ghidra_names.json]
        [--knowledge ghidra_knowledge.json]
        [--input  NAME=VALUE ...]         # known input variable values
        [--callee FUNC_NAME=RETURN_VAL]   # known callee return values
        [--goal   "what is the return value?"]
        [--depth  1]                      # also trace callees to this depth
        [--dry-run]

Examples:
    # Trace device hash with known MachineGuid
    python llm_simulate.py --va 0x181eXXXX \\
        --input  MachineGuid="{5156c52f-a042-47e5-98f0-33b04fcd81b2}" \\
        --callee BCryptHashData="hashes the input bytes into the active hash state" \\
        --goal   "does the result equal T1EE1D9C7D565CE72FA64F22E3FAB69FC?"

    # AES key path
    python llm_simulate.py --va 0x181dXXXX \\
        --input  key_bytes="1047f11ba23da61fac378d04a226489e" \\
        --input  guid_bytes="5156c52fa04247e598f033b04fcd81b2" \\
        --goal   "what is KEY1?"
"""

import os, sys, json, argparse, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Config ─────────────────────────────────────────────────────────────────────
# Paths come from ground_truth.py (H=1). Fall back to local directory if absent.

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
try:
    from ground_truth import (CALLTREE_JSON  as IN_CALLTREE,
                               NAMES_JSON     as IN_NAMES,
                               KNOWLEDGE_JSON as IN_KNOWLEDGE)
except ImportError:
    IN_CALLTREE  = os.path.join(_here, "ghidra_calltree.json")
    IN_NAMES     = os.path.join(_here, "ghidra_names.json")
    IN_KNOWLEDGE = os.path.join(_here, "ghidra_knowledge.json")
MODEL        = "claude-sonnet-4-6"
MAX_CODE_CHARS = 8000  # larger budget for simulation — full context helps

# ── Load helpers ──────────────────────────────────────────────────────────────

def load_json(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def find_func(calltree, va_str):
    """Locate a function in the calltree by VA string."""
    va_str = va_str.lower()
    for f in calltree.get("functions", []):
        if f["va"].lower() == va_str:
            return f
    return None

def resolve_callees(func, calltree, names, depth):
    """
    Build a name→pseudocode map for callees up to `depth` levels.
    depth=0 → just the target function.
    depth=1 → also inline one level of callees.
    """
    resolved = {}
    if depth < 1:
        return resolved
    func_map = {f["va"]: f for f in calltree.get("functions", [])}
    for va in func.get("called_vas", []):
        callee = func_map.get(va)
        if not callee:
            continue
        name = names.get(va, {}).get("suggested_name") or callee["name"]
        code = callee.get("pseudocode") or "/* no pseudocode */"
        if len(code) > 2000:
            code = code[:2000] + "\n/* ... truncated ... */"
        resolved[name] = {"va": va, "pseudocode": code}
    return resolved

# ── Prompt construction ────────────────────────────────────────────────────────

SYSTEM = """\
You are an expert reverse engineer doing CONCRETE EXECUTION TRACING of decompiled
C pseudocode from a NativeAOT binary.

Your task: trace through the function step by step with the provided input values.
For each step:
  1. Quote the relevant pseudocode line or condition.
  2. Substitute known values and evaluate it.
  3. State the result (variable assignment, branch direction, etc.).
  4. Flag any uncertainty (unknown pointer content, opaque external call, etc.).

At the end provide:
  RESULT    : the function's return value or observable output (or "UNKNOWN: reason")
  CONFIDENCE: high / medium / low — how certain you are of this trace
  KEY BRANCH: the single most important conditional in the function, and what flips it
  INVERSE   : if asked, what input would produce a target output — or "cannot determine"

Format your response as structured text, not JSON. Be precise with hex values.
"""

def build_simulate_prompt(func, func_name, inputs, callee_overrides,
                          resolved_callees, names, knowledge, goal):
    parts = []

    # Knowledge context
    obs = (knowledge or {}).get("observations", [])
    if obs:
        parts.append("=== BINARY CONTEXT ===")
        for o in obs[:15]:
            parts.append(f"  - {o}")
        parts.append("=== END CONTEXT ===\n")

    # Function header
    parts.append(f"FUNCTION: {func_name}  VA={func['va']}  "
                 f"depth={func.get('depth','?')}  size={func.get('size','?')}B")

    # Named callees from names file
    callee_names = {}
    for va in func.get("called_vas", []):
        named = names.get(va, {}).get("suggested_name")
        if named:
            callee_names[va] = named
    named_callees = func.get("named_callees", [])
    if callee_names or named_callees:
        parts.append("\nCallees (named):")
        for va, nm in callee_names.items():
            parts.append(f"  {va}  {nm}")
        for n in named_callees:
            if n not in callee_names.values():
                parts.append(f"        {n}")

    # Inlined callee pseudocode (if depth > 0)
    if resolved_callees:
        parts.append("\n--- CALLEE PSEUDOCODE (for context) ---")
        for cname, cinfo in resolved_callees.items():
            code = cinfo["pseudocode"]
            parts.append(f"\n// {cname}  ({cinfo['va']})")
            parts.append(code)
        parts.append("--- END CALLEES ---")

    # Target pseudocode
    code = func.get("pseudocode") or "/* no pseudocode */"
    if len(code) > MAX_CODE_CHARS:
        code = code[:MAX_CODE_CHARS] + "\n/* ... truncated ... */"
    parts.append(f"\nPseudocode:\n{code}")

    # Provided inputs
    if inputs:
        parts.append("\n--- PROVIDED INPUT VALUES ---")
        for k, v in inputs.items():
            parts.append(f"  {k} = {v}")

    # Callee behavior overrides
    if callee_overrides:
        parts.append("\n--- KNOWN CALLEE BEHAVIORS ---")
        for k, v in callee_overrides.items():
            parts.append(f"  {k}()  ->  {v}")

    # Standard WinAPI behaviors (always useful for NativeAOT)
    parts.append("""
--- STANDARD API BEHAVIORS (use these unless overridden) ---
  BCryptOpenAlgorithmProvider("MD5", ...)  -> sets up MD5 hash context
  BCryptCreateHash(alg_handle, ...)        -> creates incremental hash object
  BCryptHashData(hash, pbInput, cbInput)   -> feeds cbInput bytes from pbInput into hash
  BCryptFinishHash(hash, pbOutput, cbOutput) -> writes final hash digest to pbOutput
  RegQueryValueExW(key, "MachineGuid", ...) -> returns MachineGuid string from registry
  RoGetActivationFactory(hstring, ...)     -> WinRT activation; returns COM factory
  CryptographicBuffer.EncodeToHexString(buf) -> uppercase hex string of buffer bytes
  HardwareIdentification.GetPackageSpecificToken(null).Id -> IBuffer of hardware token bytes
""")

    # Simulation goal
    goal_str = goal or "Trace full execution and report the return value."
    parts.append(f"\n--- SIMULATION GOAL ---\n{goal_str}")
    parts.append("\nTrace the execution step by step, then give RESULT / CONFIDENCE / KEY BRANCH / INVERSE.")

    return "\n".join(parts)

# ── API call ──────────────────────────────────────────────────────────────────

def make_client():
    try:
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        return anthropic.Anthropic(api_key=key)
    except ImportError:
        print("Install anthropic: pip install anthropic")
        sys.exit(1)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--va",        required=True,       help="VA of function to simulate (e.g. 0x181e1234)")
    ap.add_argument("--calltree",  default=IN_CALLTREE, help="ghidra_calltree.json path")
    ap.add_argument("--names",     default=IN_NAMES,    help="ghidra_names.json path")
    ap.add_argument("--knowledge", default=IN_KNOWLEDGE,help="ghidra_knowledge.json path")
    ap.add_argument("--input",     action="append", default=[], metavar="NAME=VALUE",
                    help="Known input variable value; may repeat")
    ap.add_argument("--callee",    action="append", default=[], metavar="FUNC=RETVAL",
                    help="Known callee return value; may repeat")
    ap.add_argument("--goal",      default=None,        help="Simulation question/goal")
    ap.add_argument("--depth",     type=int, default=0, help="Inline callee pseudocode to this depth (0=none, 1=direct callees)")
    ap.add_argument("--dry-run",   action="store_true", help="Print prompt only, no API call")
    args = ap.parse_args()

    # Normalise VA string
    va_str = args.va.lower()
    if not va_str.startswith("0x"):
        va_str = "0x" + va_str

    # Load data files
    calltree = load_json(args.calltree)
    if not calltree:
        print(f"[ERROR] Could not load calltree: {args.calltree}")
        sys.exit(1)
    names    = load_json(args.names) if os.path.exists(args.names) else {}
    knowledge= load_json(args.knowledge) if os.path.exists(args.knowledge) else {}

    # Find function
    func = find_func(calltree, va_str)
    if not func:
        print(f"[ERROR] VA {va_str} not found in calltree.")
        print("Available VAs (first 20):")
        for f in calltree.get("functions", [])[:20]:
            print(f"  {f['va']}  {f['name']}")
        sys.exit(1)

    # Function name (use suggested if available)
    func_name = names.get(va_str, {}).get("suggested_name") or func["name"]
    print(f"Simulating: {func_name}  ({va_str})")
    print(f"  size={func.get('size','?')}B  depth={func.get('depth','?')}")

    # Parse --input and --callee key=value pairs
    inputs  = {}
    for kv in args.input:
        k, _, v = kv.partition("=")
        inputs[k.strip()] = v.strip()
    callee_overrides = {}
    for kv in args.callee:
        k, _, v = kv.partition("=")
        callee_overrides[k.strip()] = v.strip()

    # Inline callee pseudocode
    resolved_callees = resolve_callees(func, calltree, names, args.depth)
    if resolved_callees:
        print(f"  Inlining {len(resolved_callees)} callee(s) at depth={args.depth}")

    # Build prompt
    prompt = build_simulate_prompt(
        func, func_name, inputs, callee_overrides,
        resolved_callees, names, knowledge, args.goal
    )

    if args.dry_run:
        print(f"\n[DRY RUN] Prompt ({len(prompt)} chars):\n")
        print(prompt[:3000])
        if len(prompt) > 3000:
            print(f"... [{len(prompt)-3000} chars truncated]")
        return

    client = make_client()
    print(f"\nPrompt: {len(prompt)} chars. Sending to Claude...\n")
    print("=" * 70)

    resp = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    print(resp.content[0].text)
    print("=" * 70)


if __name__ == "__main__":
    main()
