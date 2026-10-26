"""
llm_name_functions.py — Tiered LLM analysis of decompiled functions.

MENTAL MODEL — Factor Graph / Belief Propagation
─────────────────────────────────────────────────
Each function is a variable node in a factor graph (the call graph).
Each call edge is a factor node that couples caller and callee beliefs.
Understanding scores are probability distributions over "what does this do?".

Belief propagation runs in two directions:
  Forward  (bottom-up):  leaves name first → understanding flows UP to callers.
  Backward (top-down):   caller context flows DOWN to refine callee understanding.

One forward + one backward pass = exact inference on a DAG (same algorithm as
backpropagation and dynamic programming). Multiple passes = convergence for graphs
with cycles (loopy BP, typically 2–4 iterations).

The compound_score implements HDG ∏pᵢ: a chain where one callee has u=0.4 caps
the entire chain at ≤0.4 × (other factors). This makes "holes" visible at the
top of the tree — a high-level function that calls an opaque helper scores low,
correctly signalling that more analysis is needed below it.

Quarantine rule (error-path / runtime):
  C++ runtime machinery (EH tables, templates, CRT) and error-path branches are
  intentionally opaque. They are classified via is_error_path / is_runtime and
  contribute 1.0 to parent scores (no upward penalty). They are never deepened.
  This implements Principle 1 (Domain Delineation) from autonomous_llm_framework.md:
  the runtime domain is solved (look it up), not novel (don't re-derive it).

Rederivation rule (already-named functions):
  If Ghidra's FunctionID or demangler already gave a function a non-FUN_ name,
  we accept it at understanding=1.0 and is_runtime=True without an LLM call.
  Looking up is always cheaper than rederiving (Search Before Derive, Principle 4).

Three-way invariant:
  Ghidra (static)         → understanding score per function
  fractal_memscan (live)  → verify() fires when K/IV pair appears in memory
  runtime_probe (Frida)   → verify() fires when BCryptHashData sees the right input
  All three write to ghidra_knowledge.json and share the same verify() ground truth.

Tiers:
  T1  Name + description + self understanding score.  Cheap.
  T2  T1 + branch_scores list + optional annotated_code with inline comments.
  T3  Use llm_simulate.py for concrete execution tracing (not done here).

Usage:
    python llm_name_functions.py [--input calltree.json]
    python llm_name_functions.py --dry-run
    python llm_name_functions.py --resume
    python llm_name_functions.py --tier 2          # request branch annotations
    python llm_name_functions.py --deepen 0.60     # re-queue low compound-score funcs at T2
    python llm_name_functions.py --holes           # print compound-score hole map, then exit
    python llm_name_functions.py --synthesize      # consolidate observations into knowledge base
    python llm_name_functions.py --apply           # push names to Ghidra
"""

import os, sys, json, argparse, re, time, datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Config ─────────────────────────────────────────────────────────────────────
# Paths come from ground_truth.py (H=1). Fall back to local directory if absent.

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
try:
    from ground_truth import (CALLTREE_JSON  as IN_DEFAULT,
                               NAMES_JSON     as NAMES_OUT,
                               KNOWLEDGE_JSON as KNOWLEDGE_OUT,
                               TARGET_DLL     as HSS_DLL)
except ImportError:
    IN_DEFAULT    = os.path.join(_here, "ghidra_calltree.json")
    NAMES_OUT     = os.path.join(_here, "ghidra_names.json")
    KNOWLEDGE_OUT = os.path.join(_here, "ghidra_knowledge.json")
    HSS_DLL       = ""
MODEL           = "claude-sonnet-4-6"
MAX_CODE_CHARS  = 6000
MAX_BATCH       = 4
HOLE_THRESHOLD  = 0.60   # compound score below this is a "hole"

# ── Anthropic client ───────────────────────────────────────────────────────────

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

# ── Knowledge base ─────────────────────────────────────────────────────────────

def load_knowledge(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"binary":"","image_base":"","observations":[],
            "subsystems":{},"open_questions":[],"updated":""}

def save_knowledge(knowledge, path):
    knowledge["updated"] = datetime.date.today().isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(knowledge, f, indent=2, ensure_ascii=False)

def add_observations(knowledge, new_obs):
    existing = set(knowledge.get("observations", []))
    added = 0
    for obs in (new_obs or []):
        obs = obs.strip()
        if obs and obs not in existing:
            knowledge.setdefault("observations", []).append(obs)
            existing.add(obs)
            added += 1
    return added

def _load_verified_facts():
    """
    Load COMMON/INVARIANT verify_hits from knowledge_bus.
    These are mathematically confirmed (K, IV) pairs — not inferences.
    Presenting them at the top of every prompt lets the LLM do RECOGNITION
    (orient to a known answer) rather than DEDUCTION (derive from scratch).
    """
    try:
        from knowledge_bus import get_verify_hits
        hits = get_verify_hits(min_stability="COMMON")
        return hits
    except Exception:
        return []

def build_knowledge_context(knowledge):
    obs  = knowledge.get("observations", [])
    subs = knowledge.get("subsystems", {})
    qns  = knowledge.get("open_questions", [])
    verified_facts = _load_verified_facts()

    if not obs and not subs and not qns and not verified_facts:
        return ""

    lines = [f"=== BINARY KNOWLEDGE: {knowledge.get('binary','?')}  "
             f"ImageBase {knowledge.get('image_base','?')} ==="]

    # ── Mathematically confirmed facts (top priority — recognition, not deduction) ──
    # These are real measured bytes confirmed by 2+ independent analysis layers.
    # When you see these values in pseudocode or as constants, you know their role.
    if verified_facts:
        lines.append("CONFIRMED BY MULTI-LAYER ANALYSIS (mathematical, not inferred):")
        for h in verified_facts:
            stab = h.get("stability", "?")
            layers = h.get("layers_seen", [])
            lines.append(f"  [{stab} — layers: {layers}]")
            lines.append(f"    KEY (K) = {h['key']}  (16 bytes)")
            lines.append(f"    IV      = {h['iv']}  (16 bytes)")
            lines.append(f"    Invariant: AES-128-CBC-Encrypt(K, IV, MachineGUID) == KEY1")
            if h.get("va_hints"):
                lines.append(f"    Observed near VAs: {h['va_hints']}")
        lines.append("")

    # ── LLM-derived observations ───────────────────────────────────────────────
    if obs:
        # Separate raw observations from the structured knowledge_bus ones
        text_obs = [o for o in obs if isinstance(o, str)]
        if text_obs:
            lines.append("Established facts (from prior analysis):")
            for o in text_obs[:25]:
                lines.append(f"  - {o}")

    if subs:
        lines.append("Known subsystems:")
        for rng, desc in list(subs.items())[:12]:
            lines.append(f"  {rng}: {desc}")

    if qns:
        lines.append("Open questions (answer if possible):")
        for q in qns[:8]:
            lines.append(f"  ? {q}")

    lines.append("=== END KNOWLEDGE ===\n")
    return "\n".join(lines)

# ── PE loader (optional) ───────────────────────────────────────────────────────

def try_load_pe(dll_path):
    if not dll_path or not os.path.isfile(dll_path):
        return None
    try:
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location(
            "pe_utils", os.path.join(here, "pe_utils.py"))
        if not spec:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.PE(dll_path)
    except Exception as e:
        print(f"[pe_utils] {e}")
        return None

# ── Compound score ─────────────────────────────────────────────────────────────

def compute_compound_score(va, names_out, calltree_map, _visited=None):
    """
    Compound score for a function = self_understanding * weighted_callee_score.

    Implements the HDG ∏pᵢ principle: if any callee is poorly understood,
    the caller's effective understanding is reduced proportionally.
    Cycles are broken by treating the cycle member as 1.0 (no penalty for recursion).
    Unnamed callees (FUN_XXX not in names_out) contribute score 0.5.
    External/imported callees are treated as 1.0 (fully known).
    """
    if _visited is None:
        _visited = set()
    if va in _visited:
        return 1.0   # cycle — no infinite recursion penalty
    _visited = _visited | {va}

    item = names_out.get(va, {})

    # Error-path and runtime-machinery functions are quarantined: they don't
    # propagate uncertainty upward (callers are not penalised for opaque error
    # handlers or C++ runtime templates they call).
    if item.get("is_error_path") or item.get("is_runtime"):
        return 1.0

    self_score = float(item.get("understanding", 0.5))

    func = calltree_map.get(va)
    if not func:
        return self_score

    callee_scores = []
    for callee_va in func.get("called_vas", []):
        callee_item = names_out.get(callee_va, {})
        # Quarantined callees don't propagate uncertainty
        if callee_item.get("is_error_path") or callee_item.get("is_runtime"):
            continue
        if callee_va in names_out:
            cs = compute_compound_score(callee_va, names_out, calltree_map, _visited)
        elif callee_va in calltree_map:
            cs = 0.5   # in calltree but not yet named
        else:
            cs = 1.0   # external import — treat as known
        callee_scores.append(cs)

    if not callee_scores:
        return self_score

    avg_callee = sum(callee_scores) / len(callee_scores)
    # Weight: self-understanding dominates (60%), callee quality matters (40%)
    return round(self_score * (0.60 + 0.40 * avg_callee), 3)

def build_hole_map(names_out, calltree_map):
    """Return {va: compound_score} for all named functions, sorted worst first."""
    scores = {}
    for va in names_out:
        scores[va] = compute_compound_score(va, names_out, calltree_map)
    return dict(sorted(scores.items(), key=lambda x: x[1]))

def print_hole_map(names_out, calltree_map):
    hole_map = build_hole_map(names_out, calltree_map)
    print(f"\n{'VA':<20}  {'Score':>6}  {'Tier':>4}  Name")
    print("-" * 80)
    holes = 0
    for va, score in hole_map.items():
        item = names_out[va]
        name = item.get("suggested_name", "?")
        tier = item.get("tier_analyzed", 1)
        is_ep = item.get("is_error_path", False)
        is_rt = item.get("is_runtime", False)
        tag   = " [err]" if is_ep else (" [rt]" if is_rt else "")
        flag  = " <-- HOLE" if score < HOLE_THRESHOLD and not is_ep and not is_rt else ""
        print(f"{va:<20}  {score:>6.3f}  T{tier:>3}  {name}{tag}{flag}")
        if score < HOLE_THRESHOLD and not is_ep and not is_rt:
            holes += 1
            opaque = item.get("opaque_callees", [])
            if opaque:
                print(f"  {'':20}         opaque: {', '.join(opaque[:4])}")
    total = len(hole_map)
    print(f"\n{total} functions  {holes} holes (compound_score < {HOLE_THRESHOLD})")

# ── Prompt system strings ──────────────────────────────────────────────────────

SYSTEM_T1 = """\
You are a reverse engineering expert analysing decompiled C pseudocode from a
NativeAOT binary (no managed metadata, no debug symbols).

For each function return a JSON object with these fields:
  suggested_name   snake_case <=50 chars — WHAT it does, not HOW
  description      one sentence <=120 chars
  confidence       "high" | "medium" | "low"  (your confidence in the NAME)
  understanding    float 0.0–1.0 — how well you understand what this function does
                   1.0 = fully clear; 0.5 = partly opaque; 0.0 = completely opaque
  opaque_callees   list of FUN_XXXXXXXX callee names you couldn't infer meaning from
  is_error_path    true if this function is PRIMARILY an error/exception handling path
                   (error reporters, cleanup-on-failure, exception propagators, etc.)
                   These are intentionally not deepened further.
  is_runtime       true if this function is C++ runtime machinery that is NOT part of
                   the application's own logic: exception tables, vtable dispatch,
                   template instantiations, CRT initializers, TLS callbacks, etc.
                   These are structurally opaque and are quarantined from compound scores.

Understanding score guidance:
  0.9–1.0  All branches clear, all key callees known
  0.7–0.9  Main path clear, minor ambiguities
  0.5–0.7  Significant opaque sections or unknown callees
  0.3–0.5  Mostly opaque; name is a guess
  0.0–0.3  Cannot determine function's purpose
  NOTE: is_error_path/is_runtime functions should still get honest understanding scores
        but they will NOT be scheduled for deeper analysis by the pipeline.

Rules:
- Base names only on demonstrably observed behavior.
- Prefer specificity: "compute_device_md5_hash" > "hash_something"
- Already-named callees are ground truth — use them.
- FUN_xxxxxxxx in callee lists are UNNAMED — do not infer meaning from them.
- If you see BCryptHashData/BCryptCreateHash calls, identify algorithm from context.
- Error paths: look for branches where the function terminates, raises, or reports
  failure without doing application work. Label is_error_path=true.
- Runtime machinery: look for multiple virtual-dispatch patterns, EH tables (__C_specific_handler,
  __except_handler, _UnwindInfo), template recursion, or CRT init sequences.
  Label is_runtime=true.

Response MUST be:
  Option A (single function):  one JSON object {...}
  Option B (batch):            JSON array  [{...}, ...]
  Option C (with observations): {"functions":[...],"observations":["binary-wide fact",...]}

Reply ONLY with valid JSON, no markdown fences.
"""

SYSTEM_T2 = """\
You are a reverse engineering expert doing DEEP analysis of decompiled C pseudocode
from a NativeAOT binary.

For each function return a JSON object with ALL T1 fields PLUS:
  branch_scores    list of {"condition": "...", "score": 0.0–1.0, "note": "..."}
                   — one entry per major if/switch branch
                   — score is YOUR confidence that you understand what that branch does
  annotated_code   the ORIGINAL pseudocode with inline comments inserted at major
                   branches showing: condition meaning, branch score, what each path does.
                   Format: // [br:0.82] <what this branch means>
                   Keep all original code intact — only ADD comments, never remove lines.
  opaque_callees   list of FUN_XXXXXXXX you couldn't resolve

understanding field: must now account for branch coverage.
  A function with all branches scored >= 0.7 should be >= 0.7.
  A function with any branch scored < 0.4 should cap at 0.5.

IMPORTANT — do NOT annotate error-path branches deeply:
  If a branch leads only to error handling, exception propagation, or C++ runtime
  machinery, mark it as // [br:skip:error-path] and move on. These branches are
  intentionally quarantined — the pipeline will not deepen them further.
  This prevents wasting analysis budget on EH tables and template instantiation chains.

Same is_error_path and is_runtime fields as T1 — set them if applicable.

Response must be one JSON object or array or {"functions":[...],"observations":[...]}.
Reply ONLY with valid JSON, no markdown fences.
"""

# ── Prompt builder ─────────────────────────────────────────────────────────────

def build_prompt(funcs, name_map, knowledge, tier=1):
    parts = []
    ctx = build_knowledge_context(knowledge)
    if ctx:
        parts.append(ctx)

    for f in funcs:
        code = f.get("pseudocode") or "/* no pseudocode */"
        if len(code) > MAX_CODE_CHARS:
            code = code[:MAX_CODE_CHARS] + "\n/* ... truncated ... */"

        # Callee context: substitute known names + show understanding scores
        callees = []
        for va in f.get("called_vas", []):
            known = name_map.get(va)
            if known:
                score = known.get("understanding", "?")
                callees.append(f"{va} ({known['name']} [u={score}])")
            else:
                callees.append(f"{va} (unnamed)")
        for n in f.get("named_callees", []):
            if not n.startswith("FUN_"):
                callees.append(n)
        callee_str = ", ".join(dict.fromkeys(callees))[:500]

        # Annotate named floors directly above the code block so LLM recognizes
        # C++ runtime / error-path without spending deductive budget on it
        floor_note = ""
        item_in_map = name_map.get(f["va"], {})
        floors = f.get("floors", []) + (["RUNTIME"] if item_in_map.get("is_runtime") else [])
        floors += (["ERROR_PATH"] if item_in_map.get("is_error_path") else [])
        if floors:
            floor_note = f"[FLOORS: {', '.join(set(floors))}] "

        parts.append(f"""
--- FUNCTION {f['va']} (depth={f['depth']}, size={f['size']}B) ---
{floor_note}Current Ghidra name: {f['name']}
Calls: {callee_str or '(none detected)'}
Pseudocode:
{code}
""")

    prompt = "\n".join(parts)
    tier_str = "T2 deep analysis (include branch_scores + annotated_code)" \
               if tier >= 2 else "T1 naming"
    prompt += f"""
---
Perform {tier_str} for EACH of the {len(funcs)} function(s) above.
Reply ONLY with the JSON.
"""
    return prompt

# ── API call + response parsing ────────────────────────────────────────────────

def call_llm(client, prompt, system, dry_run=False):
    if dry_run:
        print(f"[DRY RUN] prompt {len(prompt)} chars")
        print(prompt[:1000], "...")
        return None
    resp = client.messages.create(
        model=MODEL,
        max_tokens=4096 if "annotated_code" in prompt else 2048,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text

def _normalise_item(item, va_fallback):
    """Ensure required fields exist with sensible defaults."""
    item.setdefault("va", va_fallback)
    item.setdefault("understanding", 0.5)
    item.setdefault("opaque_callees", [])
    item.setdefault("branch_scores", [])
    item.setdefault("tier_analyzed", 1)
    item.setdefault("is_error_path", False)
    item.setdefault("is_runtime", False)
    # Clamp understanding to [0, 1]
    try:
        item["understanding"] = max(0.0, min(1.0, float(item["understanding"])))
    except (TypeError, ValueError):
        item["understanding"] = 0.5
    return item

def parse_response(text, batch_vas, tier):
    """Returns (func_dict, observations_list)."""
    if text is None:
        return {}, []
    text = re.sub(r"^```[a-z]*\n?", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"```$", "", text.strip(), flags=re.MULTILINE)
    try:
        parsed = json.loads(text)
    except Exception as e:
        print(f"  [WARN] JSON parse failed: {e}")
        print(f"  Raw: {text[:400]}")
        return {}, []

    observations = []
    if isinstance(parsed, dict) and "functions" in parsed:
        observations = parsed.get("observations", [])
        parsed = parsed["functions"]

    if isinstance(parsed, dict) and "va" in parsed:
        parsed = [parsed]   # single function returned as object

    if not isinstance(parsed, list):
        print(f"  [WARN] Unexpected JSON shape: {type(parsed)}")
        return {}, []

    result = {}
    for item in parsed:
        if "va" not in item:
            continue
        va = item["va"]
        item["tier_analyzed"] = tier
        result[va] = _normalise_item(item, va)

    return result, observations

# ── Synthesis ──────────────────────────────────────────────────────────────────

SYNTHESIZE_SYSTEM = """\
You are a reverse engineering expert. Given a complete set of named+scored functions
from a NativeAOT binary, produce a structured architectural knowledge summary.

Reply ONLY with valid JSON (no markdown):
{
  "observations":   ["concise binary-wide architectural fact", ...],
  "subsystems":     {"range_or_label": "what it does", ...},
  "open_questions": ["unresolved question", ...]
}
Focus on non-obvious patterns: calling conventions, subsystem boundaries, crypto flows,
data structure layouts, initialisation sequences.
"""

def synthesize_knowledge(client, names_out, tree, knowledge, dry_run=False):
    print("\nSynthesizing knowledge from named functions...")
    lines = [
        f"Binary: {tree.get('program','?')}  ImageBase: {tree.get('imagebase','?')}",
        f"Functions: {len(names_out)}\n",
    ]
    for va, item in sorted(names_out.items()):
        cs = item.get("compound_score", item.get("understanding", "?"))
        lines.append(
            f"  {va}  u={item.get('understanding',0):.2f}  cs={cs!s:<6}  "
            f"[{item.get('confidence','?')}]  "
            f"{item.get('suggested_name','?'):40s}  {item.get('description','')}")
    prompt = "\n".join(lines) + "\n\nSynthesize. Reply with the JSON object."
    if dry_run:
        print(f"[DRY RUN] synth prompt {len(prompt)} chars")
        return
    resp_text = call_llm(client, prompt, system=SYNTHESIZE_SYSTEM)
    if not resp_text:
        return
    resp_text = re.sub(r"^```[a-z]*\n?", "", resp_text.strip(), flags=re.MULTILINE)
    resp_text = re.sub(r"```$", "", resp_text.strip(), flags=re.MULTILINE)
    try:
        synth = json.loads(resp_text)
        added  = add_observations(knowledge, synth.get("observations", []))
        new_s  = synth.get("subsystems", {})
        knowledge.setdefault("subsystems", {}).update(new_s)
        existing_q = set(knowledge.get("open_questions", []))
        new_q = 0
        for q in synth.get("open_questions", []):
            if q not in existing_q:
                knowledge.setdefault("open_questions", []).append(q)
                existing_q.add(q)
                new_q += 1
        print(f"  +{added} observations  +{len(new_s)} subsystems  +{new_q} questions")
    except Exception as e:
        print(f"  [WARN] Synthesis parse failed: {e}\n  Raw: {resp_text[:300]}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",      default=IN_DEFAULT,    help="Input calltree JSON")
    ap.add_argument("--output",     default=NAMES_OUT,     help="Output names JSON")
    ap.add_argument("--knowledge",  default=KNOWLEDGE_OUT, help="Knowledge base JSON")
    ap.add_argument("--dll",        default=HSS_DLL,       help="DLL path for PE VA validation")
    ap.add_argument("--batch",      type=int, default=1,   help="Functions per LLM call")
    ap.add_argument("--tier",       type=int, default=1,   choices=[1,2],
                    help="Analysis tier: 1=naming+score, 2=+branch annotations")
    ap.add_argument("--deepen",     type=float, default=None, metavar="THRESHOLD",
                    help="After naming, re-queue functions with compound_score < THRESHOLD at T2")
    ap.add_argument("--holes",      action="store_true",
                    help="Print compound-score hole map for already-named functions, then exit")
    ap.add_argument("--dry-run",    action="store_true",   help="Print prompts, no API calls")
    ap.add_argument("--resume",     action="store_true",   help="Skip already-named VAs")
    ap.add_argument("--apply",      action="store_true",   help="Apply names back to Ghidra")
    ap.add_argument("--depth",      type=int, default=None)
    ap.add_argument("--min-size",   type=int, default=20)
    ap.add_argument("--synthesize", action="store_true")
    args = ap.parse_args()

    # PE validation (optional)
    pe = try_load_pe(args.dll)
    if pe:
        print(pe.summary())
        print()

    # Load calltree
    print(f"Loading {args.input}...")
    with open(args.input, encoding="utf-8") as f:
        tree = json.load(f)
    funcs = tree["functions"]
    calltree_map = {f["va"]: f for f in funcs}
    print(f"Loaded {len(funcs)} functions from {tree['program']}  "
          f"(image base {tree['imagebase']})")

    # Cross-check image base
    if pe:
        ct_base = int(tree["imagebase"], 16) if isinstance(tree["imagebase"], str) \
                  else tree["imagebase"]
        if ct_base != pe.image_base:
            print(f"  [WARN] calltree imagebase 0x{ct_base:x} != "
                  f"PE header 0x{pe.image_base:x}")
        else:
            print(f"  [OK] imagebase matches PE header: 0x{pe.image_base:x}")
        if funcs:
            va_s = int(funcs[0]["va"], 16)
            print(f"  [VA] {pe.describe_va(va_s)}")

    # Load knowledge
    knowledge = load_knowledge(args.knowledge)
    if not knowledge.get("binary"):
        knowledge["binary"]     = tree["program"]
        knowledge["image_base"] = tree["imagebase"]
    obs_count = len(knowledge.get("observations", []))
    print(f"  [knowledge] {obs_count} observations loaded")

    # Load existing names
    names_out = {}
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            names_out = json.load(f)

    # --holes: just print compound scores and exit
    if args.holes:
        if not names_out:
            print("No named functions yet.")
            return
        print_hole_map(names_out, calltree_map)
        return

    # Filters
    if args.depth is not None:
        funcs = [f for f in funcs if f["depth"] <= args.depth]
        print(f"Filtered to depth<={args.depth}: {len(funcs)} functions")
    if args.min_size:
        funcs = [f for f in funcs if f["size"] >= args.min_size]
        print(f"Filtered to size>={args.min_size}: {len(funcs)} functions")

    # Resume
    if args.resume and names_out:
        already = sum(1 for f in funcs if f["va"] in names_out)
        print(f"Resuming: {already} already named, {len(funcs)-already} to go")
        funcs = [f for f in funcs if f["va"] not in names_out]

    # ── Fast-path: accept Ghidra-named functions without LLM call ─────────────
    # Implements "Search Before Derive" (Principle 4, autonomous_llm_framework.md):
    # if Ghidra's FunctionID or demangler already named a function, treat it as
    # known (understanding=1.0, is_runtime=True) rather than re-deriving from pseudocode.
    # This covers CRT functions, MSVC STL templates, and any EH helper Ghidra matched.
    pre_named = 0
    still_unknown = []
    for f in funcs:
        name = f.get("name", "")
        if name and not name.startswith("FUN_") and not name.startswith("thunk_FUN_"):
            # Ghidra already gave it a real name — accept at face value
            va = f["va"]
            if va not in names_out:
                names_out[va] = {
                    "va":            va,
                    "suggested_name": name,
                    "description":   f"Ghidra-identified: {name}",
                    "confidence":    "high",
                    "understanding": 1.0,
                    "is_runtime":    True,
                    "tier_analyzed": 0,
                    "opaque_callees":[],
                    "branch_scores": [],
                }
                pre_named += 1
        else:
            still_unknown.append(f)
    if pre_named:
        print(f"  [fast-path] {pre_named} functions accepted from Ghidra names "
              f"(no LLM call needed)")
    funcs = still_unknown

    # Sort deepest first
    funcs.sort(key=lambda x: (-x["depth"], x["va"]))

    client = make_client() if not args.dry_run else None
    system = SYSTEM_T2 if args.tier >= 2 else SYSTEM_T1

    total_prompt_chars = 0
    batch_size = min(args.batch, MAX_BATCH)

    def run_batch(batch, tier):
        nonlocal total_prompt_chars
        print(f"\n[T{tier}] Naming: {', '.join(f['va'] for f in batch)}")
        # Build name_map with understanding scores for context
        name_map = {}
        for v, item in names_out.items():
            name_map[v] = {"name": item.get("suggested_name", "?"),
                           "understanding": item.get("understanding", 0.5)}
        prompt = build_prompt(batch, name_map, knowledge, tier=tier)
        total_prompt_chars += len(prompt)
        if args.dry_run:
            if total_prompt_chars <= len(prompt):   # first batch
                print(prompt[:2000])
            return
        try:
            raw = call_llm(client, prompt, system)
            parsed, observations = parse_response(raw, [f["va"] for f in batch], tier)
        except Exception as e:
            print(f"  [ERROR] {e}")
            time.sleep(2)
            return
        for item in parsed.values():
            va  = item["va"]
            u   = item.get("understanding", 0.5)
            br  = len(item.get("branch_scores", []))
            ann = bool(item.get("annotated_code"))
            names_out[va] = item
            print(f"  {va}  u={u:.2f}  "
                  f"{'branches='+str(br) if br else '':12s}  "
                  f"{'[annotated]' if ann else '':12s}  "
                  f"{item.get('suggested_name','?'):38s}  "
                  f"[{item.get('confidence','?')}]  "
                  f"{item.get('description','')[:50]}")
        if observations:
            added = add_observations(knowledge, observations)
            if added:
                print(f"  [knowledge] +{added} observation(s)")
        # Persist after every batch
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(names_out, f, indent=2, ensure_ascii=False)
        save_knowledge(knowledge, args.knowledge)
        time.sleep(0.3)

    # ── T1 pass ────────────────────────────────────────────────────────────────
    for i in range(0, len(funcs), batch_size):
        batch = funcs[i:i + batch_size]
        run_batch(batch, args.tier)

    # ── Compute compound scores ────────────────────────────────────────────────
    if not args.dry_run and names_out:
        print("\nComputing compound scores...")
        for va, item in names_out.items():
            item["compound_score"] = compute_compound_score(va, names_out, calltree_map)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(names_out, f, indent=2, ensure_ascii=False)
        holes = sum(1 for item in names_out.values()
                    if item["compound_score"] < HOLE_THRESHOLD)
        print(f"  {len(names_out)} functions  {holes} holes "
              f"(compound_score < {HOLE_THRESHOLD})")

    # ── Auto-deepen (optional) ─────────────────────────────────────────────────
    if args.deepen is not None and not args.dry_run and names_out:
        threshold = args.deepen
        to_deepen = [
            calltree_map[va] for va, item in names_out.items()
            if item.get("compound_score", 1.0) < threshold
            and item.get("tier_analyzed", 1) < 2
            and not item.get("is_error_path")
            and not item.get("is_runtime")
            and va in calltree_map
        ]
        if to_deepen:
            print(f"\nDeepening {len(to_deepen)} functions with compound_score < {threshold}...")
            to_deepen.sort(key=lambda x: (-x["depth"], x["va"]))
            for i in range(0, len(to_deepen), batch_size):
                run_batch(to_deepen[i:i + batch_size], tier=2)
            # Recompute after deepening
            for va, item in names_out.items():
                item["compound_score"] = compute_compound_score(va, names_out, calltree_map)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(names_out, f, indent=2, ensure_ascii=False)
        else:
            print(f"\nNo functions below threshold {threshold} — nothing to deepen.")

    print(f"\nDone. {len(names_out)} functions named.")
    print(f"Prompt chars sent: {total_prompt_chars:,}")
    print(f"Output:    {args.output}")
    print(f"Knowledge: {args.knowledge}  "
          f"({len(knowledge.get('observations',[]))} observations)")

    if args.synthesize and not args.dry_run and names_out:
        synthesize_knowledge(client, names_out, tree, knowledge)
        save_knowledge(knowledge, args.knowledge)

    if args.apply:
        apply_names(args.output, tree)


# ── Apply names to Ghidra ──────────────────────────────────────────────────────

def apply_names(names_path, tree):
    print("\nApplying names to Ghidra project...")
    try:
        import pyghidra
    except ImportError:
        print("pyghidra not available. Use py -3.13")
        return
    with open(names_path, encoding="utf-8") as f:
        names = json.load(f)
    script_lines = [
        "# @runtime PyGhidra",
        "# @title Apply LLM function names",
        "from ghidra.program.model.symbol import SourceType",
        f"NAMES = {json.dumps({v: d['suggested_name'] for v, d in names.items()})}",
        "fm = currentProgram.getFunctionManager()",
        "af = currentProgram.getAddressFactory().getDefaultAddressSpace()",
        "applied = 0",
        "for va_str, name in NAMES.items():",
        "    addr = af.getAddress(va_str)",
        "    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)",
        "    if func and func.getName().startswith('FUN_'):",
        "        tx = currentProgram.startTransaction('rename')",
        "        try:",
        "            func.setName(name, SourceType.USER_DEFINED)",
        "            applied += 1",
        "        finally:",
        "            currentProgram.endTransaction(tx, True)",
        "print('Applied ' + str(applied) + ' names')",
    ]
    apply_script = r"C:\Users\nathan37\Desktop\ghidra_apply_names.py"
    with open(apply_script, "w") as f:
        f.write("\n".join(script_lines))
    import subprocess
    result = subprocess.run(
        ["py", "-3.13", "-m", "pyghidra.ghidra_launch",
         "--install-dir", r"C:\Users\nathan37\Desktop\ghidra",
         "ghidra.app.util.headless.AnalyzeHeadless",
         r"C:\Users\nathan37\Desktop\hss_proj", "hss_project",
         "-process", "Hss.Store.Client.dll",
         "-postScript", apply_script,
         "-scriptPath", r"C:\Users\nathan37\Desktop"],
        capture_output=True, text=True)
    print(result.stdout[-2000:] if result.stdout else "(no output)")
    if result.returncode != 0:
        print("stderr:", result.stderr[-1000:])


if __name__ == "__main__":
    main()
