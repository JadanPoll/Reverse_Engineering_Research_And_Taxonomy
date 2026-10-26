"""
knowledge_bus.py — Single write channel into the shared knowledge base.

All three analysis layers write discoveries here. The bus applies
stability tiers borrowed from memory_invariants.py methodology:

  EPHEMERAL  — seen in exactly 1 layer / 1 session
  COMMON     — seen in 2+ independent sources (layers or sessions)
  INVARIANT  — seen in ALL three layers, or confirmed by verify() in 2+ sessions

This implements the three-way invariant at the KNOWLEDGE level (not just the
oracle level). verify() tells you whether a candidate is correct. The bus tells
you how many independent times that has been confirmed — so a single lucky hit
can't be mistaken for ground truth.

Usage (any layer):
    from knowledge_bus import emit_discovery, emit_verify_hit

    # When fractal_memscan fires verify():
    emit_verify_hit("memscan", key_hex, iv_hex,
                    va_hint=0x..., context={"addr": 0x..., "region": "heap"})

    # When runtime_probe sees BCryptHashData with a matching output:
    emit_verify_hit("frida",   key_hex, iv_hex,
                    va_hint=0x..., context={"hook": "BCryptHashData", "arg_idx": 2})

    # General observation (LLM naming, function role, etc.):
    emit_discovery("ghidra", "function_role",
                   {"va": "0x182d904e0", "role": "loads AES key from frozen blob"})

Schema written to KNOWLEDGE_JSON:
{
  "observations": [
    {
      "id":          "sha1 of (layer+obs_type+canonical_key)",
      "layer":       "ghidra" | "memscan" | "frida",
      "obs_type":    "verify_hit" | "function_role" | "string_ref" | ...,
      "payload":     {...},
      "first_seen":  ISO timestamp,
      "last_seen":   ISO timestamp,
      "count":       N (how many times this exact obs arrived),
      "stability":   "EPHEMERAL" | "COMMON" | "INVARIANT",
      "layers_seen": ["ghidra", "memscan"]   (for verify_hit)
    }
  ],
  "verify_hits": [
    {
      "key":          "hex",
      "iv":           "hex",
      "layers_seen":  ["memscan", "frida"],
      "stability":    "COMMON",
      "first_seen":   ISO,
      "last_seen":    ISO,
      "count":        2
    }
  ],
  "subsystems": {...},        # preserved from llm_name_functions synthesize
  "open_questions": [...],    # preserved
  "knowledge_version": 2
}
"""

import os, sys, json, hashlib, datetime

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

try:
    from ground_truth import KNOWLEDGE_JSON
except Exception:
    KNOWLEDGE_JSON = os.path.join(_here, "ghidra_knowledge.json")

ALL_LAYERS = {"ghidra", "memscan", "frida", "dynamic"}

# ── Stability tier (borrowed from memory_invariants.py) ───────────────────────

def _stability(layers_seen: list, count: int) -> str:
    """
    INVARIANT  = confirmed by all three layers, or seen 5+ times
    COMMON     = confirmed by 2+ layers, or seen 3+ times in one layer
    EPHEMERAL  = seen once or twice in one layer only
    """
    n_layers = len(set(layers_seen))
    if n_layers >= 3 or count >= 5:
        return "INVARIANT"
    if n_layers >= 2 or count >= 3:
        return "COMMON"
    return "EPHEMERAL"

def _obs_id(layer: str, obs_type: str, canonical_key: str) -> str:
    h = hashlib.sha1(f"{obs_type}:{canonical_key}".encode()).hexdigest()[:12]
    return h

def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Load / save ───────────────────────────────────────────────────────────────

def _load() -> dict:
    if not os.path.exists(KNOWLEDGE_JSON):
        return {"observations": [], "verify_hits": [], "subsystems": {},
                "open_questions": [], "knowledge_version": 2}
    try:
        with open(KNOWLEDGE_JSON, encoding="utf-8") as f:
            data = json.load(f)
        # Migrate v1 (from llm_name_functions) to v2 if needed
        if "knowledge_version" not in data:
            data.setdefault("verify_hits", [])
            data["knowledge_version"] = 2
        return data
    except Exception:
        return {"observations": [], "verify_hits": [], "subsystems": {},
                "open_questions": [], "knowledge_version": 2}

def _save(data: dict):
    tmp = KNOWLEDGE_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, KNOWLEDGE_JSON)   # atomic on Windows (same volume)

# ── Public API ────────────────────────────────────────────────────────────────

def emit_verify_hit(layer: str, key_hex: str, iv_hex: str,
                    va_hint: int = 0, context: dict = None):
    """
    Record a verify() confirmation from `layer`.
    Escalates stability as more layers confirm the same (key, iv) pair.

    layer: "ghidra" | "memscan" | "frida"
    """
    key_hex = key_hex.lower().replace(" ", "")
    iv_hex  = iv_hex.lower().replace(" ", "")
    canonical = f"{key_hex}:{iv_hex}"

    data = _load()
    hits  = data.setdefault("verify_hits", [])

    existing = next((h for h in hits if h["key"] == key_hex and h["iv"] == iv_hex), None)
    now = _now()
    if existing:
        if layer not in existing["layers_seen"]:
            existing["layers_seen"].append(layer)
        existing["count"]      += 1
        existing["last_seen"]   = now
        existing["stability"]   = _stability(existing["layers_seen"], existing["count"])
        if va_hint and va_hint not in existing.get("va_hints", []):
            existing.setdefault("va_hints", []).append(hex(va_hint))
        if context:
            existing.setdefault("contexts", []).append({**context, "layer": layer, "ts": now})
    else:
        entry = {
            "key":         key_hex,
            "iv":          iv_hex,
            "layers_seen": [layer],
            "stability":   "EPHEMERAL",
            "first_seen":  now,
            "last_seen":   now,
            "count":       1,
            "va_hints":    [hex(va_hint)] if va_hint else [],
            "contexts":    [{**context, "layer": layer, "ts": now}] if context else [],
        }
        hits.append(entry)
        existing = entry

    # Also add a structured observation record
    obs_id = _obs_id(layer, "verify_hit", canonical)
    obs = data.setdefault("observations", [])
    existing_obs = next((o for o in obs if o.get("id") == obs_id), None)
    if existing_obs:
        existing_obs["count"]    += 1
        existing_obs["last_seen"] = now
        if layer not in existing_obs.get("layers_seen", []):
            existing_obs["layers_seen"].append(layer)
        existing_obs["stability"] = _stability(existing_obs["layers_seen"], existing_obs["count"])
    else:
        obs.append({
            "id":          obs_id,
            "layer":       layer,
            "obs_type":    "verify_hit",
            "payload":     {"key": key_hex, "iv": iv_hex,
                            "va_hint": hex(va_hint) if va_hint else None},
            "first_seen":  now,
            "last_seen":   now,
            "count":       1,
            "stability":   "EPHEMERAL",
            "layers_seen": [layer],
        })

    _save(data)

    # Print stability escalation to stderr so it's visible in all tool outputs
    stab = existing["stability"]
    n_layers = len(set(existing["layers_seen"]))
    if stab == "INVARIANT":
        print(f"\n{'!'*70}", file=sys.stderr)
        print(f"  KNOWLEDGE INVARIANT: verify() confirmed by {n_layers}/3 layers, {existing['count']}x total", file=sys.stderr)
        print(f"  K  = {key_hex}", file=sys.stderr)
        print(f"  IV = {iv_hex}", file=sys.stderr)
        print(f"  Layers: {existing['layers_seen']}", file=sys.stderr)
        print(f"{'!'*70}\n", file=sys.stderr)
    elif stab == "COMMON":
        print(f"\n[KB] COMMON verify_hit: {n_layers} layers, {existing['count']}x  K={key_hex[:8]}...  IV={iv_hex[:8]}...", file=sys.stderr)


def emit_discovery(layer: str, obs_type: str, payload: dict):
    """
    Record a general observation from any analysis layer.
    obs_type: "function_role" | "string_ref" | "callee_behavior" | "asm_pattern" | ...
    payload: free-form dict; include "va" key if relevant to a function.
    """
    canonical = json.dumps(payload, sort_keys=True)
    obs_id = _obs_id(layer, obs_type, canonical)

    data = _load()
    obs  = data.setdefault("observations", [])
    now  = _now()

    existing = next((o for o in obs if o.get("id") == obs_id), None)
    if existing:
        existing["count"]    += 1
        existing["last_seen"] = now
        if layer not in existing.get("layers_seen", []):
            existing["layers_seen"].append(layer)
        existing["stability"] = _stability(existing["layers_seen"], existing["count"])
    else:
        obs.append({
            "id":          obs_id,
            "layer":       layer,
            "obs_type":    obs_type,
            "payload":     payload,
            "first_seen":  now,
            "last_seen":   now,
            "count":       1,
            "stability":   "EPHEMERAL",
            "layers_seen": [layer],
        })

    _save(data)


def get_verify_hits(min_stability: str = "EPHEMERAL") -> list[dict]:
    """
    Return verify_hits at or above min_stability.
    min_stability: "EPHEMERAL" < "COMMON" < "INVARIANT"
    """
    order = {"EPHEMERAL": 0, "COMMON": 1, "INVARIANT": 2}
    floor = order.get(min_stability, 0)
    data  = _load()
    return [h for h in data.get("verify_hits", [])
            if order.get(h.get("stability", "EPHEMERAL"), 0) >= floor]


def emit_field_access(struct_key: str, offset: int, field_name: str,
                      layer: str, func_va: str = None, evidence: str = None):
    """
    Record a confirmed struct field: struct_key at byte offset maps to field_name.
    Called by dynamic layer (Frida StructObserver) or manual annotation.
    Escalates to COMMON once two layers confirm the same (struct_key, offset, field_name).
    """
    payload: dict = {"struct_key": struct_key, "offset": hex(offset), "field_name": field_name}
    if func_va:
        payload["func_va"] = func_va
    if evidence:
        payload["evidence"] = evidence
    emit_discovery(layer, "field_access", payload)


def get_field_map(struct_key: str = None,
                  min_stability: str = "COMMON") -> dict:
    """
    Return confirmed field offset→name mappings at or above min_stability.
    struct_key=None  → {struct_key: {offset_hex: field_name}}  (all structs)
    struct_key given → {offset_hex: field_name}                (one struct)
    """
    obs = get_observations(obs_type="field_access", min_stability=min_stability)
    result: dict = {}
    for o in obs:
        p   = o["payload"]
        sk  = p.get("struct_key", "unknown")
        off = p.get("offset", "0x0")
        nm  = p.get("field_name", "?")
        if struct_key is None:
            result.setdefault(sk, {})[off] = nm
        elif sk == struct_key:
            result[off] = nm
    return result


def get_observations(layer: str = None, obs_type: str = None,
                     min_stability: str = "EPHEMERAL") -> list[dict]:
    order = {"EPHEMERAL": 0, "COMMON": 1, "INVARIANT": 2}
    floor = order.get(min_stability, 0)
    data  = _load()
    result = []
    for obs in data.get("observations", []):
        if layer and obs.get("layer") != layer:
            continue
        if obs_type and obs.get("obs_type") != obs_type:
            continue
        if order.get(obs.get("stability", "EPHEMERAL"), 0) < floor:
            continue
        result.append(obs)
    return result


# ── Self-test ──────────────────────────────────────────────────────────────────

def _verify():
    import tempfile, os as _os

    # Use a temp file so _verify() doesn't pollute the real knowledge base
    global KNOWLEDGE_JSON
    orig = KNOWLEDGE_JSON
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        KNOWLEDGE_JSON = tmp.name

    try:
        # POSITIVE: first hit from one layer → EPHEMERAL
        emit_verify_hit("memscan", "aabbccdd" * 4, "11223344" * 4)
        hits = get_verify_hits()
        assert len(hits) == 1
        assert hits[0]["stability"] == "EPHEMERAL", f"Expected EPHEMERAL, got {hits[0]['stability']}"

        # POSITIVE: same pair from second layer → COMMON
        emit_verify_hit("frida", "aabbccdd" * 4, "11223344" * 4)
        hits = get_verify_hits()
        assert hits[0]["stability"] == "COMMON"
        assert set(hits[0]["layers_seen"]) == {"memscan", "frida"}

        # POSITIVE: same pair from third layer → INVARIANT
        emit_verify_hit("ghidra", "aabbccdd" * 4, "11223344" * 4)
        hits = get_verify_hits()
        assert hits[0]["stability"] == "INVARIANT"
        assert set(hits[0]["layers_seen"]) == {"memscan", "frida", "ghidra"}

        # NEGATIVE: different pair must stay separate
        emit_verify_hit("memscan", "deadbeef" * 4, "cafebabe" * 4)
        hits = get_verify_hits()
        assert len(hits) == 2

        # POSITIVE: min_stability filter
        common_up = get_verify_hits(min_stability="COMMON")
        assert len(common_up) == 1   # only the INVARIANT one qualifies as >= COMMON
        assert common_up[0]["key"] == "aabbccdd" * 4

        # POSITIVE: general observation
        emit_discovery("ghidra", "function_role",
                       {"va": "0x182d904e0", "role": "loads AES key"})
        obs = get_observations(obs_type="function_role")
        assert len(obs) == 1
        assert obs[0]["stability"] == "EPHEMERAL"  # only one layer so far

        # POSITIVE: field_access — single layer → EPHEMERAL (below COMMON threshold)
        emit_field_access("CryptoCtx", 0x18, "size", "dynamic", func_va="0x1234")
        fmap = get_field_map("CryptoCtx", min_stability="COMMON")
        assert fmap == {}, f"Expected empty map (EPHEMERAL only), got {fmap}"

        # POSITIVE: second layer → COMMON, now visible
        emit_field_access("CryptoCtx", 0x18, "size", "ghidra", func_va="0x1234")
        fmap = get_field_map("CryptoCtx", min_stability="COMMON")
        assert fmap == {"0x18": "size"}, f"Expected field map, got {fmap}"

        # POSITIVE: all-structs form
        all_maps = get_field_map(min_stability="COMMON")
        assert "CryptoCtx" in all_maps
        assert all_maps["CryptoCtx"]["0x18"] == "size"

        # POSITIVE: different struct does not pollute CryptoCtx map
        emit_field_access("KeyCtx", 0x18, "len", "dynamic")
        emit_field_access("KeyCtx", 0x18, "len", "frida")
        fmap_crypto = get_field_map("CryptoCtx", min_stability="COMMON")
        assert fmap_crypto == {"0x18": "size"}, f"Cross-struct pollution: {fmap_crypto}"

        print("OK: knowledge_bus.py verified")
        print(f"  Stability tiers confirmed: EPHEMERAL -> COMMON -> INVARIANT")
        print(f"  Cross-layer escalation confirmed")
        print(f"  min_stability filter confirmed")
        print(f"  field_access emit/get confirmed")

    finally:
        KNOWLEDGE_JSON = orig
        _os.unlink(tmp.name)


if __name__ == "__main__":
    _verify()
