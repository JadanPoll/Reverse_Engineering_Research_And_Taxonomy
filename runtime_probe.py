"""
runtime_probe.py — Frida-based runtime analysis framework for HSS.

This is the "GDB layer" in the three-way RE invariant:
  Ghidra (static)         → pseudocode understanding scores
  fractal_memscan (live)  → spatial memory change tracking + verify() check
  runtime_probe (runtime) → live function argument/return capture + verify() check

The three layers share the same verify() ground truth:
  AES-128-CBC-Encrypt(K, IV, MachineGUID) == KEY1

When any layer observes bytes that satisfy verify(), it is a definitive discovery.
This runtime layer observes the actual arguments flowing through functions.

Why Frida, not GDB/CDB:
  CDB disrupts UWP AppContainer capability checks (0x80070005, HSS exits).
  Frida's user-mode injection survives AppContainer if run as Administrator.

MODES:
  --probe bcrypt      Hook BCryptHashData/BCryptFinishHash — capture all hash inputs
                      and outputs, automatically run verify() on 16-byte outputs.
  --probe reg         Hook RegQueryValueExW — capture all registry reads (MachineGuid).
  --probe va 0x...    Hook arbitrary function by VA — dump args/return + call stack.
  --probe calls 0x... Trace all calls FROM a function (capture the callee VA + args).
  --probe memory 0x.. Read memory at VA (no hook, just snapshot).
  --probe all         All hooks at once.

Usage:
  python runtime_probe.py                          # auto-detect HSS, all hooks
  python runtime_probe.py --probe bcrypt           # BCrypt only
  python runtime_probe.py --probe va 0x182d904e0   # hook specific function
  python runtime_probe.py --pid 1234 --timeout 60
  python runtime_probe.py --mem 0x181eb1df8        # read memory snapshot

Output: structured JSON lines to stdout + verify() hits to stderr for visibility.
"""

import sys, os, json, argparse, time, frida
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Mathematical invariant ────────────────────────────────────────────────────
# Imported from ground_truth.py (H=1). All three analysis layers share this gate:
#   Ghidra (static), fractal_memscan (dynamic), runtime_probe (Frida live).

import sys as _sys, os as _os
_here = _os.path.dirname(_os.path.abspath(__file__))
if _here not in _sys.path:
    _sys.path.insert(0, _here)

try:
    from ground_truth import verify
    _HAS_VERIFY = True
except Exception:
    def verify(key: bytes, iv: bytes) -> bool:
        return False   # no ground_truth.py — oracle disabled
    _HAS_VERIFY = False

try:
    from knowledge_bus import emit_verify_hit as _kb_emit_verify_hit
    _HAS_KB = True
except Exception:
    _HAS_KB = False
    def _kb_emit_verify_hit(*a, **kw): pass

_seen_16byte_blocks: list[tuple[str, bytes]] = []   # (label, bytes) for pair-checking

def check_16byte(label: str, data: bytes):
    """Check data for 16-byte slices that might be K or IV. Print on hit."""
    if not _HAS_VERIFY:
        return
    candidates = []
    for i in range(0, len(data) - 15, 1):   # every offset, not just aligned
        c = data[i:i+16]
        if c != b'\x00'*16:
            candidates.append((f"{label}+{i}", c))
    for lbl, c in candidates:
        for prev_lbl, prev in _seen_16byte_blocks:
            if verify(c, prev):
                _emit_verify_hit(lbl, c, prev_lbl, prev)
            elif verify(prev, c):
                _emit_verify_hit(prev_lbl, prev, lbl, c)
    _seen_16byte_blocks.extend(candidates)

def _emit_verify_hit(k_lbl, k, iv_lbl, iv):
    msg = {
        "event":  "VERIFY_HIT",
        "K_label": k_lbl,  "K":  k.hex(),
        "IV_label": iv_lbl, "IV": iv.hex(),
    }
    print(f"\n{'!'*70}", file=sys.stderr)
    print(f"  VERIFY HIT  K={k.hex()}  IV={iv.hex()}", file=sys.stderr)
    print(f"  K from:  {k_lbl}", file=sys.stderr)
    print(f"  IV from: {iv_lbl}", file=sys.stderr)
    print(f"{'!'*70}\n", file=sys.stderr, flush=True)
    emit(msg)
    # Write to knowledge bus — escalates stability if memscan or ghidra already confirmed
    _kb_emit_verify_hit("frida", k.hex(), iv.hex(),
                        context={"k_label": k_lbl, "iv_label": iv_lbl})

def emit(obj: dict):
    """Write a structured JSON event line to stdout."""
    print(json.dumps(obj), flush=True)

# ── Frida JS snippets ─────────────────────────────────────────────────────────

JS_BCRYPT = r"""
'use strict';

// ── BCryptHashData ─────────────────────────────────────────────────────────
// Captures every buffer fed into any hash operation.
// Useful for: MD5(HardwareIdentification token), SHA*, HMAC inputs.
const BCryptHashData = Module.findExportByName('Bcrypt.dll', 'BCryptHashData');
if (BCryptHashData) {
    Interceptor.attach(BCryptHashData, {
        onEnter: function(args) {
            const handle  = args[0].toString();
            const pbInput = args[1];
            const cbInput = args[2].toInt32();
            if (cbInput <= 0 || cbInput > 65536) return;
            try {
                const raw  = Array.from(new Uint8Array(pbInput.readByteArray(cbInput)));
                const hex  = raw.map(b => b.toString(16).padStart(2,'0')).join('');
                let str16  = '';
                try { str16 = pbInput.readUtf16String(Math.min(cbInput/2, 200)); } catch(e){}
                send({ type: 'BCryptHashData',
                       handle: handle, len: cbInput, hex: hex, str16: str16 });
            } catch(e) {}
        }
    });
    send({ type: 'status', msg: 'BCryptHashData hooked' });
}

// ── BCryptFinishHash ───────────────────────────────────────────────────────
// Captures the final hash output. For MD5 this is 16 bytes — run verify() on it.
const BCryptFinishHash = Module.findExportByName('Bcrypt.dll', 'BCryptFinishHash');
if (BCryptFinishHash) {
    Interceptor.attach(BCryptFinishHash, {
        onEnter: function(args) {
            this.pbOutput = args[1];
            this.cbOutput = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) return;
            if (!this.pbOutput || this.cbOutput <= 0 || this.cbOutput > 64) return;
            try {
                const raw = Array.from(new Uint8Array(this.pbOutput.readByteArray(this.cbOutput)));
                const hex = raw.map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
                send({ type: 'BCryptFinishHash', len: this.cbOutput, hex: hex });
            } catch(e) {}
        }
    });
    send({ type: 'status', msg: 'BCryptFinishHash hooked' });
}

// ── BCryptCreateHash ───────────────────────────────────────────────────────
// Records algorithm name when a hash context is created.
const BCryptCreateHash = Module.findExportByName('Bcrypt.dll', 'BCryptCreateHash');
if (BCryptCreateHash) {
    Interceptor.attach(BCryptCreateHash, {
        onEnter: function(args) {
            try {
                const alg = args[0].readUtf16String();
                send({ type: 'BCryptCreateHash', algorithm: alg });
            } catch(e) {}
        }
    });
    send({ type: 'status', msg: 'BCryptCreateHash hooked' });
}
"""

JS_REG = r"""
'use strict';
const RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
if (RegQueryValueExW) {
    Interceptor.attach(RegQueryValueExW, {
        onEnter: function(args) {
            try {
                this.valueName = args[1].readUtf16String();
                this.lpData    = args[4];
                this.lpcbData  = args[5];
            } catch(e) { this.valueName = '?'; }
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) return;
            const interesting = ['MachineGuid','ProductId','DeviceId','DigitalProductId',
                                 'InstallDate','SystemProductName'];
            const n = this.valueName || '';
            if (!interesting.some(k => n.toLowerCase().includes(k.toLowerCase()))) return;
            try {
                let value = '';
                if (this.lpData && !this.lpData.isNull() &&
                    this.lpcbData && !this.lpcbData.isNull()) {
                    const len = this.lpcbData.readU32();
                    if (len > 0 && len <= 1024) {
                        try { value = this.lpData.readUtf16String(Math.floor(len/2)); }
                        catch(e) {
                            const raw = this.lpData.readByteArray(Math.min(len, 64));
                            value = Array.from(new Uint8Array(raw))
                                        .map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
                        }
                    }
                }
                send({ type: 'RegQueryValueExW', name: n, value: value });
            } catch(e) {}
        }
    });
    send({ type: 'status', msg: 'RegQueryValueExW hooked' });
}
"""

def js_va_hook(va_hex: str, func_label: str, arg_count: int = 6) -> str:
    """
    Generate Frida JS to hook an arbitrary function by VA.
    Captures: all integer/pointer args, return value, call stack (3 frames).
    arg_count: how many args to capture (default 6, covers most x64 ABI cases).
    """
    args_capture = "\n".join(
        f"            args_out.push({{ idx: {i}, val: args[{i}].toString() }});"
        for i in range(arg_count)
    )
    return f"""
'use strict';
(function() {{
    const va = ptr('{va_hex}');
    const label = '{func_label}';
    Interceptor.attach(va, {{
        onEnter: function(args) {{
            this.enter_ts = Date.now();
            var args_out = [];
{args_capture}
            // Try reading first arg as a string (often a name/path arg)
            var str_hint = '';
            try {{ str_hint = args[0].readUtf16String(64); }} catch(e) {{}}
            send({{ type: 'fn_enter', va: '{va_hex}', label: label,
                    args: args_out, str_hint: str_hint }});
        }},
        onLeave: function(retval) {{
            send({{ type: 'fn_leave', va: '{va_hex}', label: label,
                    retval: retval.toString(),
                    elapsed_ms: Date.now() - this.enter_ts }});
        }}
    }});
    send({{ type: 'status', msg: 'hooked ' + label + ' at ' + '{va_hex}' }});
}})();
"""

def js_struct_hook(va_hex: str, label: str, arg_idx: int = 0,
                   offsets: list[int] | None = None,
                   read_before: bool = True, read_after: bool = True) -> str:
    """
    Hook a function and read struct fields from one of its pointer arguments.

    For each call, emits a 'struct_snapshot' event with the value at every
    requested offset.  Reading after the call (read_after=True) captures
    mutations — diff before/after to see exactly which fields the function wrote.

    offsets: list of byte offsets to read from the struct pointer.
             Default: [0,4,8,0xc,0x10,0x14,0x18,0x1c,0x20,0x28,0x30,0x38,0x40]
    """
    if offsets is None:
        offsets = [0,4,8,0xc,0x10,0x14,0x18,0x1c,0x20,0x28,0x30,0x38,0x40,0x48,0x50]

    offsets_js = json.dumps(offsets)
    before_code = """
            const snap_before = readFields(this.struct_ptr, offsets);
            this.snap_before = snap_before;
            send({ type: 'struct_snapshot', phase: 'enter', va: VA, label: LABEL,
                   arg_idx: ARG_IDX, fields: snap_before });
""" if read_before else "this.snap_before = null;"

    after_code = """
            if (this.struct_ptr && !this.struct_ptr.isNull()) {
                const snap_after = readFields(this.struct_ptr, offsets);
                const mutations = [];
                if (this.snap_before) {
                    for (let i = 0; i < snap_after.length; i++) {
                        const b = this.snap_before[i], a = snap_after[i];
                        if (b && a && b.u64 !== a.u64)
                            mutations.push({ offset: a.offset, before: b.u64, after: a.u64 });
                    }
                }
                send({ type: 'struct_snapshot', phase: 'leave', va: VA, label: LABEL,
                       arg_idx: ARG_IDX, fields: snap_after, mutations: mutations,
                       retval: retval.toString() });
            }
""" if read_after else ""

    return f"""
'use strict';
(function() {{
    const VA      = '{va_hex}';
    const LABEL   = '{label}';
    const ARG_IDX = {arg_idx};
    const offsets = {offsets_js};

    function readFields(base, offs) {{
        const out = [];
        for (const off of offs) {{
            try {{
                const p = base.add(off);
                out.push({{
                    offset:  off,
                    u64:     p.readU64().toString(),
                    u32:     p.readU32(),
                    u8:      p.readU8(),
                    bytes8:  Array.from(new Uint8Array(p.readByteArray(8)))
                                  .map(b => b.toString(16).padStart(2,'0')).join(''),
                }});
            }} catch(e) {{
                out.push({{ offset: off, error: e.message }});
            }}
        }}
        return out;
    }}

    Interceptor.attach(ptr(VA), {{
        onEnter: function(args) {{
            this.enter_ts = Date.now();
            try {{
                this.struct_ptr = args[ARG_IDX];
                if (this.struct_ptr.isNull()) {{ this.struct_ptr = null; return; }}
                {before_code}
            }} catch(e) {{ this.struct_ptr = null; }}
        }},
        onLeave: function(retval) {{
            try {{
                {after_code}
            }} catch(e) {{}}
        }}
    }});
    send({{ type: 'status', msg: 'struct hook active: ' + LABEL + ' arg[' + ARG_IDX + ']' }});
}})();
"""


def js_call_tracer(va_hex: str, label: str) -> str:
    """
    Use Frida Stalker to trace every call made FROM the hooked function.

    This resolves virtual dispatch and indirect calls that are invisible to
    Ghidra's static analysis.  For each call site within the function, emits
    a 'callee_call' event with the actual target VA — the real callee, not the
    vtable slot placeholder.
    """
    return f"""
'use strict';
(function() {{
    const VA    = '{va_hex}';
    const LABEL = '{label}';

    Interceptor.attach(ptr(VA), {{
        onEnter: function(args) {{
            this.tid = Process.getCurrentThreadId();
            this.callees = [];
            const self = this;
            Stalker.follow(this.tid, {{
                events: {{ call: true, ret: false, exec: false }},
                onReceive: function(events) {{
                    const reader = Stalker.parse(events, {{ annotate: false }});
                    for (const ev of reader) {{
                        if (ev[0] === 'call') {{
                            self.callees.push({{ site: ev[1].toString(), target: ev[2].toString() }});
                        }}
                    }}
                }}
            }});
        }},
        onLeave: function(retval) {{
            Stalker.unfollow(this.tid);
            Stalker.flush();
            if (this.callees.length > 0) {{
                send({{ type: 'callee_trace', va: VA, label: LABEL,
                        callees: this.callees, retval: retval.toString() }});
            }}
        }}
    }});
    send({{ type: 'status', msg: 'callee tracer active: ' + LABEL }});
}})();
"""


def js_register_tracer(va_hex: str, label: str,
                       watch_sections: list[dict] | None = None) -> str:
    """
    Capture register state at function entry and exit, plus non-stack memory writes.

    Entry snapshot: Windows x64 ABI integer args — RCX, RDX, R8, R9 + RSP.
    Exit snapshot:  RAX (return value) + RCX/RDX (callee-preserved check).
    Memory writes:  Stalker transform + putCallout on MOV-to-memory instructions
                    that target non-stack addresses. Catches global state mutations
                    that MemoryObserver (before/after diff) would miss if transient.

    watch_sections: list of {base: '0x...', size: N} dicts for the DLL's writable
                    sections. If provided, only writes to those ranges are reported,
                    filtering out heap/stack noise. Pass executor.pe section info.

    Emits events:
        reg_entry  — {va, label, rcx, rdx, r8, r9, rsp}
        reg_exit   — {va, label, rax, rcx, rdx, elapsed_ms}
        mem_write  — {va, label, target_addr, from_instr, value_u64}

    Usage in Python (after frida.attach):
        script.load(); script.exports.enableTracer()
        # call the target function in the app
        # collect events
    """
    sections_js = "null"
    if watch_sections:
        parts = [f'{{base: ptr("{s["base"]}"), size: {s["size"]}}}' for s in watch_sections]
        sections_js = "[" + ", ".join(parts) + "]"

    return f"""
'use strict';
(function() {{
    const VA      = '{va_hex}';
    const LABEL   = '{label}';
    const WATCHES = {sections_js};   // null = report all non-stack writes

    function inWatchedSection(addr) {{
        if (WATCHES === null) return true;
        const a = addr.toUInt32();   // only lower 32 bits for range check (sufficient)
        for (const w of WATCHES) {{
            const base = w.base.toUInt32();
            if (a >= base && a < base + w.size) return true;
        }}
        return false;
    }}

    Interceptor.attach(ptr(VA), {{
        onEnter: function(args) {{
            this.enter_ts = Date.now();
            this.tid = Process.getCurrentThreadId();
            const ctx = this.context;

            // Windows x64 ABI: first 4 integer args in RCX, RDX, R8, R9
            send({{ type: 'reg_entry', va: VA, label: LABEL,
                    rcx: ctx.rcx.toString(), rdx: ctx.rdx.toString(),
                    r8:  ctx.r8.toString(),  r9:  ctx.r9.toString(),
                    rsp: ctx.rsp.toString() }});

            const self = this;
            this.writes = [];

            // Stalker transform: intercept store instructions to non-stack addresses
            Stalker.follow(this.tid, {{
                transform: function(iterator) {{
                    let instr = iterator.next();
                    while (instr !== null) {{
                        const mnem  = instr.mnemonic;
                        const opStr = instr.opStr;
                        // Store instructions with memory destination, excluding stack
                        if ((mnem === 'mov' || mnem === 'movq' || mnem === 'movdqu'
                             || mnem === 'movaps') &&
                            opStr.indexOf('[') === 0 &&              // dest is memory
                            opStr.indexOf('rsp') === -1 &&           // not stack-relative
                            opStr.indexOf('rbp') === -1) {{           // not frame-relative
                            const instrAddr = instr.address.toString();
                            iterator.putCallout(function(ctx2) {{
                                // Compute effective address: parse [reg + offset] from opStr
                                // Simplified: we record that a non-stack write happened at this IP
                                // Full address recovery requires opStr parsing (done in Python handler)
                                send({{ type: 'mem_write', va: VA, label: LABEL,
                                        from_instr: instrAddr,
                                        rax: ctx2.rax.toString(),
                                        rcx: ctx2.rcx.toString(),
                                        rdx: ctx2.rdx.toString(),
                                        r8:  ctx2.r8.toString(),
                                        r9:  ctx2.r9.toString() }});
                            }});
                        }}
                        iterator.keep();
                        instr = iterator.next();
                    }}
                }}
            }});
        }},

        onLeave: function(retval) {{
            Stalker.unfollow(this.tid);
            Stalker.flush();
            const ctx = this.context;
            send({{ type: 'reg_exit', va: VA, label: LABEL,
                    rax: retval.toString(),
                    rcx: ctx.rcx.toString(), rdx: ctx.rdx.toString(),
                    elapsed_ms: Date.now() - this.enter_ts }});
        }}
    }});

    send({{ type: 'status', msg: 'register tracer active: ' + LABEL + ' @ ' + VA }});
}})();
"""


def js_memory_read(va_hex: str, size: int = 256) -> str:
    """Read `size` bytes at `va_hex` and send as a single event."""
    return f"""
'use strict';
(function() {{
    try {{
        const ptr_ = ptr('{va_hex}');
        const data = Array.from(new Uint8Array(ptr_.readByteArray({size})));
        const hex  = data.map(b => b.toString(16).padStart(2,'0')).join('');
        send({{ type: 'memory_read', va: '{va_hex}', size: {size}, hex: hex }});
    }} catch(e) {{
        send({{ type: 'error', va: '{va_hex}', msg: e.toString() }});
    }}
}})();
"""

# ── StructObserver ────────────────────────────────────────────────────────────

class StructObserver:
    """
    Accumulate struct field observations across many live calls.
    After min_calls observations, infer the type of each field and emit
    the inference to the knowledge bus.

    Type inference rules (applied per offset, across all observed values):
      BOOL        — only {0, 1} seen
      SMALL_INT   — all values in [0, 65535]; likely count, index, flags, enum
      UINT32      — all values fit in 32 bits; no high-32-bit variation
      POINTER     — values in plausible address range (>= 0x1000_0000)
      INT64       — any value has bits 32-63 set
      CONSTANT    — all observations identical
      UNKNOWN     — field read errored or no observations
    """

    def __init__(self, min_calls: int = 5):
        self.min_calls  = min_calls
        # { offset_int: list[int] }  — raw u64 values (errors omitted)
        self._samples: dict[int, list[int]] = {}
        self._call_count = 0
        self._mutations: list[dict] = []   # {offset, before, after} across all calls

    def record_snapshot(self, fields: list[dict], mutations: list[dict] | None = None):
        self._call_count += 1
        for f in fields:
            if "error" in f:
                continue
            off = f["offset"]
            try:
                val = int(f["u64"])
            except (ValueError, TypeError):
                continue
            self._samples.setdefault(off, []).append(val)
        if mutations:
            self._mutations.extend(mutations)

    def _infer_type(self, values: list[int]) -> str:
        if not values:
            return "UNKNOWN"
        unique = set(values)
        if unique == {0} or unique == {1} or unique <= {0, 1}:
            return "BOOL"
        if all(v >= 0x10000000 for v in values):
            return "POINTER"
        if any(v > 0xFFFFFFFF for v in values):
            return "INT64"
        if all(v <= 0xFFFF for v in values):
            return "SMALL_INT"
        if all(v <= 0xFFFFFFFF for v in values):
            return "UINT32"
        return "INT64"

    def ready(self) -> bool:
        return self._call_count >= self.min_calls

    def report(self, func_va: str, arg_idx: int) -> list[dict]:
        """
        Return inferred field descriptors and emit each to knowledge_bus.
        Call only after self.ready() is True.
        """
        results = []
        for off, vals in sorted(self._samples.items()):
            unique = sorted(set(vals))
            type_hint = self._infer_type(vals)
            is_const = len(unique) == 1

            field = {
                "offset":     off,
                "offset_hex": hex(off),
                "type_hint":  "CONSTANT" if is_const else type_hint,
                "n_samples":  len(vals),
                "unique_vals": unique[:8],   # cap to keep JSON small
                "always_zero": all(v == 0 for v in vals),
            }
            results.append(field)

            # Mutated fields are HIGH VALUE — this function WRITES to them
            mutated_offs = {m["offset"] for m in self._mutations}
            if off in mutated_offs:
                field["mutated"] = True
                field["note"]    = "function WRITES this field"

            # Emit to knowledge bus
            if _HAS_KB:
                try:
                    from knowledge_bus import emit_discovery
                    emit_discovery("frida", f"struct_field:{hex(off)}", {
                        "func_va":    func_va,
                        "arg_idx":    arg_idx,
                        "type_hint":  field["type_hint"],
                        "n_samples":  field["n_samples"],
                        "unique_vals": field["unique_vals"],
                        "mutated":    off in mutated_offs,
                    })
                except Exception:
                    pass

        return results


# ── Message handler ───────────────────────────────────────────────────────────

_bcrypt_inputs: list[str]   = []
_struct_observers: dict[str, StructObserver] = {}   # va_hex → StructObserver
_callee_maps: dict[str, dict[str, int]] = {}         # va_hex → {target_va: count}

def on_message(msg, _data):
    if msg['type'] == 'error':
        print(f"[FRIDA ERROR] {msg.get('description','?')} @ {msg.get('stack','')[:200]}",
              file=sys.stderr)
        return
    if msg['type'] != 'send':
        return

    p = msg['payload']
    t = p.get('type', '')

    if t == 'status':
        print(f"[HOOK] {p['msg']}", file=sys.stderr)

    elif t == 'BCryptCreateHash':
        event = {"event": "BCryptCreateHash", "algorithm": p.get('algorithm','')}
        emit(event)
        print(f"[BCRYPT] CreateHash algorithm={p.get('algorithm','')}", file=sys.stderr)

    elif t == 'BCryptHashData':
        hex_data = p.get('hex', '')
        s16      = p.get('str16', '').strip()
        _bcrypt_inputs.append(hex_data)
        event = {"event": "BCryptHashData",
                 "len": p.get('len'), "hex": hex_data, "str16": s16}
        emit(event)
        label = f"BCryptHashData[{len(_bcrypt_inputs)}]"
        disp  = f"  utf16={s16!r}" if s16 and len(s16) > 2 else ""
        print(f"[HASH ] len={p.get('len',0):5d}  {hex_data[:64]}{'...' if len(hex_data)>64 else ''}{disp}",
              file=sys.stderr)
        # Check each 16-byte slice against verify()
        try:
            raw = bytes.fromhex(hex_data)
            check_16byte(label, raw)
        except Exception:
            pass

    elif t == 'BCryptFinishHash':
        hex_data = p.get('hex', '')
        event = {"event": "BCryptFinishHash", "len": p.get('len'), "hex": hex_data}
        emit(event)
        print(f"[HASH ] FINISH len={p.get('len',0):3d}  {hex_data}", file=sys.stderr)
        try:
            raw = bytes.fromhex(hex_data)
            check_16byte(f"BCryptFinishHash", raw)
        except Exception:
            pass

    elif t == 'RegQueryValueExW':
        event = {"event": "RegQueryValueExW",
                 "name": p.get('name'), "value": p.get('value')}
        emit(event)
        print(f"[REG  ] {p.get('name')} = {p.get('value')!r}", file=sys.stderr)
        # If this looks like a GUID or key material, check it
        val = p.get('value', '')
        if val and len(val) == 36 and val.count('-') == 4:
            # It's a GUID string — convert to bytes (little-endian Windows GUID encoding)
            raw_hex = val.replace('-', '')
            try:
                raw = bytes.fromhex(raw_hex)
                check_16byte(f"reg:{p.get('name')}", raw)
            except Exception:
                pass

    elif t == 'fn_enter':
        event = {"event": "fn_enter", "va": p.get('va'), "label": p.get('label'),
                 "args": p.get('args'), "str_hint": p.get('str_hint')}
        emit(event)
        args_str = "  ".join(f"arg{a['idx']}={a['val']}" for a in p.get('args', []))
        hint = f"  str0={p.get('str_hint')!r}" if p.get('str_hint') else ""
        print(f"[CALL ] {p.get('label')}({args_str}){hint}", file=sys.stderr)

    elif t == 'fn_leave':
        event = {"event": "fn_leave", "va": p.get('va'), "label": p.get('label'),
                 "retval": p.get('retval'), "elapsed_ms": p.get('elapsed_ms')}
        emit(event)
        print(f"[RET  ] {p.get('label')} -> {p.get('retval')}  "
              f"({p.get('elapsed_ms')}ms)", file=sys.stderr)

    elif t == 'memory_read':
        event = {"event": "memory_read", "va": p.get('va'),
                 "size": p.get('size'), "hex": p.get('hex')}
        emit(event)
        hex_d = p.get('hex','')
        print(f"[MEM  ] {p.get('va')}  {hex_d[:64]}{'...' if len(hex_d)>64 else ''}",
              file=sys.stderr)
        try:
            raw = bytes.fromhex(hex_d)
            check_16byte(f"mem:{p.get('va')}", raw)
        except Exception:
            pass

    elif t == 'struct_snapshot':
        va     = p.get('va', '?')
        label  = p.get('label', va)
        phase  = p.get('phase', 'enter')
        fields = p.get('fields', [])
        muts   = p.get('mutations', [])
        arg_i  = p.get('arg_idx', 0)

        obs = _struct_observers.setdefault(va, StructObserver())
        if phase == 'leave':
            obs.record_snapshot(fields, muts)

        emit({"event": "struct_snapshot", "va": va, "label": label,
              "phase": phase, "arg_idx": arg_i,
              "fields": fields, "mutations": muts,
              "retval": p.get('retval')})

        if phase == 'enter':
            # Print a compact summary: offset=value for first 6 non-zero fields
            nonzero = [f for f in fields if not f.get('error') and f.get('u32', 0) != 0][:6]
            field_str = "  ".join(f"+{hex(f['offset'])}={f['u64']}" for f in nonzero)
            print(f"[STRUCT] {label}  {field_str}", file=sys.stderr)

        if muts:
            for m in muts:
                print(f"[MUT  ] {label}  +{hex(m['offset'])}  "
                      f"{m['before']} -> {m['after']}", file=sys.stderr)

        # After min_calls, print and emit type inference
        if obs.ready() and obs._call_count == obs.min_calls:
            inferred = obs.report(va, arg_i)
            print(f"\n[INFER] {label} struct layout after {obs._call_count} calls:",
                  file=sys.stderr)
            for f in inferred:
                mut_tag = " *WRITTEN*" if f.get("mutated") else ""
                print(f"  +{f['offset_hex']:>6}  {f['type_hint']:<12}  "
                      f"seen={f['n_samples']}  "
                      f"vals={f['unique_vals'][:4]}"
                      f"{mut_tag}", file=sys.stderr)
            print(f"  → emitted {len(inferred)} struct_field observations to knowledge_bus\n",
                  file=sys.stderr)

    elif t == 'callee_trace':
        va       = p.get('va', '?')
        label    = p.get('label', va)
        callees  = p.get('callees', [])
        retval   = p.get('retval', '?')

        emit({"event": "callee_trace", "va": va, "label": label,
              "callees": callees, "retval": retval})

        cmap = _callee_maps.setdefault(va, {})
        for c in callees:
            tgt = c.get('target', '?')
            cmap[tgt] = cmap.get(tgt, 0) + 1

        # Print unique callees with counts
        unique_targets = sorted(cmap.items(), key=lambda x: -x[1])
        print(f"[CALLS] {label}  {len(callees)} calls this invocation  "
              f"{len(unique_targets)} unique targets total:", file=sys.stderr)
        for tgt, cnt in unique_targets[:8]:
            sym = ''
            print(f"  -> {tgt}  (×{cnt}){sym}", file=sys.stderr)

        # Emit to knowledge bus: resolved callee is HIGH VALUE
        if _HAS_KB:
            try:
                from knowledge_bus import emit_discovery
                for tgt, cnt in unique_targets:
                    emit_discovery("frida", "resolved_callee", {
                        "caller_va": va,
                        "caller_label": label,
                        "callee_va": tgt,
                        "call_count": cnt,
                        "note": "virtual dispatch or indirect call resolved at runtime"
                    })
            except Exception:
                pass

    elif t == 'reg_entry':
        # Windows x64: RCX/RDX/R8/R9 are the first 4 integer arguments
        print(f"[REGS↓] {p.get('label','')}  "
              f"RCX={p.get('rcx','?')}  RDX={p.get('rdx','?')}  "
              f"R8={p.get('r8','?')}  R9={p.get('r9','?')}", file=sys.stderr)
        print(json.dumps({**p, "type": "reg_entry"}))

    elif t == 'reg_exit':
        print(f"[REGS↑] {p.get('label','')}  "
              f"RAX={p.get('rax','?')}  elapsed={p.get('elapsed_ms','?')}ms", file=sys.stderr)
        print(json.dumps({**p, "type": "reg_exit"}))

        # Emit to KB: register profile helps cross-correlate with static analysis
        if _HAS_KB:
            try:
                from knowledge_bus import emit_discovery
                emit_discovery("frida", "register_profile", {
                    "va":    p.get("va"),
                    "label": p.get("label"),
                    "rax":   p.get("rax"),
                })
            except Exception:
                pass

    elif t == 'mem_write':
        # Non-stack memory write detected during function execution
        # from_instr = VA of the store instruction; registers at that point captured
        print(f"[WRITE] {p.get('label','')}  "
              f"@instr={p.get('from_instr','?')}  "
              f"RCX={p.get('rcx','?')}  RDX={p.get('rdx','?')}", file=sys.stderr)
        print(json.dumps({**p, "type": "mem_write"}))

    elif t == 'error':
        print(f"[ERR  ] {p.get('va','')} {p.get('msg','')}", file=sys.stderr)

# ── Process attachment ────────────────────────────────────────────────────────

def find_hss_pid() -> tuple[int | None, str]:
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        n = proc.name.lower()
        if any(k in n for k in ('hss', 'hotspot', 'anchorfree')):
            return proc.pid, proc.name
    return None, ''

def attach(pid: int) -> frida.core.Session:
    device = frida.get_local_device()
    try:
        return device.attach(pid)
    except Exception as e:
        print(f"Attach failed: {e}", file=sys.stderr)
        print("  Ensure you are running as Administrator.", file=sys.stderr)
        sys.exit(1)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Frida-based runtime probe for HSS")
    ap.add_argument('--pid',     type=int,  default=None)
    ap.add_argument('--timeout', type=int,  default=30,
                    help='Capture duration in seconds (default 30; 0 = until Ctrl-C)')
    ap.add_argument('--probe',   nargs='+', default=['all'],
                    help='What to probe: bcrypt reg all  va:<hex>  mem:<hex>')
    ap.add_argument('--mem',     default=None,
                    help='Read memory at this VA (hex) and exit — no hooks')
    args = ap.parse_args()

    # Resolve PID
    if args.pid:
        pid, name = args.pid, f'PID {args.pid}'
    else:
        pid, name = find_hss_pid()
        if not pid:
            print("HSS not found. Start HSS first.", file=sys.stderr)
            device = frida.get_local_device()
            for p in device.enumerate_processes():
                if any(k in p.name.lower() for k in ('hss','hotspot','anchor')):
                    print(f"  PID {p.pid}  {p.name}", file=sys.stderr)
            sys.exit(1)

    print(f"Attaching to {name} (PID {pid})...", file=sys.stderr)
    session = attach(pid)

    if not _HAS_VERIFY:
        print("[WARN] pycryptodome not installed — verify() disabled", file=sys.stderr)

    scripts = []

    # ── Memory read mode (no hooks) ───────────────────────────────────────────
    if args.mem:
        va_hex = args.mem if args.mem.startswith('0x') else '0x' + args.mem
        js = js_memory_read(va_hex, size=256)
        sc = session.create_script(js)
        sc.on('message', on_message)
        sc.load()
        time.sleep(0.5)
        sc.unload()
        session.detach()
        return

    # ── Hook mode ─────────────────────────────────────────────────────────────
    probes = set(args.probe)
    js_parts = []

    if 'all' in probes or 'bcrypt' in probes:
        js_parts.append(JS_BCRYPT)
    if 'all' in probes or 'reg' in probes:
        js_parts.append(JS_REG)

    # Custom VA hooks: --probe va:0x182d904e0  or  --probe va:0x182d904e0:label:6
    for p in probes:
        if p.startswith('va:') or p.startswith('0x'):
            parts = p.lstrip('va:').split(':')
            va_hex  = parts[0] if parts[0].startswith('0x') else '0x' + parts[0]
            label   = parts[1] if len(parts) > 1 else f"fn_{va_hex}"
            n_args  = int(parts[2]) if len(parts) > 2 else 6
            js_parts.append(js_va_hook(va_hex, label, n_args))

    # Struct field reader: --probe struct:VA:arg_idx:off1,off2,...
    # Example: --probe struct:0x182d904e0:0:0,8,0x18,0x28
    for p in probes:
        if p.startswith('struct:'):
            tok = p[len('struct:'):].split(':')
            va_hex  = tok[0] if tok[0].startswith('0x') else '0x' + tok[0]
            arg_idx = int(tok[1]) if len(tok) > 1 else 0
            label   = f"struct_{va_hex}"
            if len(tok) > 2 and tok[2]:
                offs = [int(o, 0) for o in tok[2].split(',') if o]
            else:
                offs = None   # use default set
            js_parts.append(js_struct_hook(va_hex, label, arg_idx, offs))

    # Callee tracer: --probe calls:VA
    # Example: --probe calls:0x182d904e0
    for p in probes:
        if p.startswith('calls:'):
            va_raw  = p[len('calls:'):]
            va_hex  = va_raw if va_raw.startswith('0x') else '0x' + va_raw
            label   = f"calltrace_{va_hex}"
            js_parts.append(js_call_tracer(va_hex, label))

    # Register tracer: --probe regs:VA  or  --probe regs:VA:label
    # Captures RCX/RDX/R8/R9 at entry, RAX at exit, non-stack writes during execution.
    # Example: --probe regs:0x182d904e0
    for p in probes:
        if p.startswith('regs:'):
            tok    = p[len('regs:'):].split(':')
            va_raw = tok[0]
            va_hex = va_raw if va_raw.startswith('0x') else '0x' + va_raw
            label  = tok[1] if len(tok) > 1 else f"regs_{va_hex}"
            js_parts.append(js_register_tracer(va_hex, label))

    if not js_parts:
        print("[WARN] No hooks selected — use --probe bcrypt|reg|all|va:0x...",
              file=sys.stderr)
        session.detach()
        return

    combined_js = "\n;\n".join(js_parts)
    script = session.create_script(combined_js)
    script.on('message', on_message)
    script.load()

    duration = args.timeout
    print(f"Hooks active. Capturing for {duration}s (0 = Ctrl-C only)...",
          file=sys.stderr)
    try:
        if duration > 0:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    script.unload()
    session.detach()
    print("\nDone.", file=sys.stderr)
    print(f"BCrypt inputs seen: {len(_bcrypt_inputs)}", file=sys.stderr)
    print(f"Candidate 16-byte blocks: {len(_seen_16byte_blocks)}", file=sys.stderr)
    if _HAS_VERIFY:
        print(f"verify() active (pycryptodome found)", file=sys.stderr)

if __name__ == '__main__':
    main()
