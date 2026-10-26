"""
ground_truth.py — THE ONLY TARGET-SPECIFIC FILE IN THE TOOLKIT.

Fill this in once for your target binary. Every other tool imports from here.
Running this file directly verifies your configuration against the real binary.

Principle: H=1 for every fact referenced by more than one tool.
  - verify()     : the mathematical oracle → imported by fractal_memscan, runtime_probe
  - KNOWN_VAS    : function entry points   → imported by ghidra_dump_calltree
  - KNOWN_STRINGS: string seed VAs         → imported by ghidra_dump_calltree
  - IMAGE_BASE   : confirmed from PE header → imported by all VA-math tools
  - *_JSON paths : artifact file locations → imported by llm_name_functions, analyze

Usage:
    python ground_truth.py       # run _verify(): confirms binary + invariant
"""

import os, sys

# ── Target binary ─────────────────────────────────────────────────────────────
# Set TARGET_DLL to the absolute path of the PE/DLL you are analysing.
# IMAGE_BASE must match the value in the PE optional header (use pe_utils or
# a hex editor to confirm before filling this in).

TARGET_DLL  = r"C:\path\to\your\target.dll"   # ← replace with your binary
IMAGE_BASE  = 0x180000000                       # ← replace with PE ImageBase

# ── Artifact paths (all tools write/read here) ─────────────────────────────────

_HERE          = os.path.dirname(os.path.abspath(__file__))
CALLTREE_JSON  = os.path.join(_HERE, "ghidra_calltree.json")
NAMES_JSON     = os.path.join(_HERE, "ghidra_names.json")
KNOWLEDGE_JSON = os.path.join(_HERE, "ghidra_knowledge.json")

# ── Known function entry points ────────────────────────────────────────────────
#
# VAs confirmed via debugger call stacks or static analysis. Passed as
# FUNCTION_SEEDS to ghidra_dump_calltree.py so Ghidra walks the call graph
# from known roots.
#
# Add new entries as analysis reveals them. Format: "descriptive_label": VA
# Labels must be unique; they are used as keys in the knowledge base.

KNOWN_VAS = {
    # "example_function":  0x180001234,   # ← replace with real VAs
}

# ── Known string literal VAs ───────────────────────────────────────────────────
#
# Raw char-array addresses of string literals in the binary (e.g. NativeAOT
# frozen objects for .NET, or rodata strings for native code).
# These are resolved to functions via Ghidra xrefs (Pass 2, best-effort).
# KNOWN_VAS is the primary analysis path; strings are supplementary seeds.

KNOWN_STRINGS = {
    # 0x180001000: "some known string",   # ← replace with real VAs + strings
}

# ── Mathematical invariant ─────────────────────────────────────────────────────
#
# The ORACLE. Every analysis layer (Ghidra static, fractal_memscan live,
# runtime_probe Frida) gates candidate (key, iv) pairs through this function.
# A hit is definitive: no layer can lie about this.
#
# Fill in the cryptographic relationship you are trying to confirm, along with
# known (input, output) pairs captured from the running binary. The verify()
# function below is a template; adapt the algorithm to match your target.
#
# Example relationship: AES-128-CBC-Encrypt(K, IV, plaintext) == ciphertext
#
# Known pairs — add more as new captures are made:
_PAIRS = [
    # (expected_output_bytes, known_input_bytes)
    # e.g. (bytes.fromhex("aabbccdd..."), bytes.fromhex("11223344...")),
]

try:
    from Crypto.Cipher import AES as _AES
    def verify(key: bytes, iv: bytes) -> bool:
        """True iff the candidate (key, iv) satisfies the oracle for any known pair."""
        if len(key) != 16 or len(iv) != 16:
            return False
        for expected_ct, plaintext in _PAIRS:
            ct = _AES.new(key, _AES.MODE_CBC, iv=iv).encrypt(plaintext)
            if ct == expected_ct:
                return True
        return False
    _HAS_VERIFY = True
except ImportError:
    def verify(key: bytes, iv: bytes) -> bool:
        return False
    _HAS_VERIFY = False


# ── Self-test ──────────────────────────────────────────────────────────────────

def _verify():
    """
    Confirm this file's claims against the real binary and observed I/O.
    POSITIVE and NEGATIVE cases per Principle 1 of the design doc.
    """
    import struct

    # ── Structural check: binary exists and imagebase matches ──────────────────
    if not os.path.exists(TARGET_DLL):
        raise FileNotFoundError(f"TARGET_DLL not found: {TARGET_DLL}")

    with open(TARGET_DLL, 'rb') as f:
        dos = f.read(0x40)
    assert dos[:2] == b'MZ', "TARGET_DLL is not a PE file"
    e_lfanew = struct.unpack_from('<I', dos, 0x3c)[0]
    with open(TARGET_DLL, 'rb') as f:
        f.seek(e_lfanew + 24)
        opt_magic = struct.unpack('<H', f.read(2))[0]
        assert opt_magic == 0x20b, f"Expected PE32+ (0x20b), got 0x{opt_magic:x}"
        f.seek(e_lfanew + 24 + 24)
        image_base = struct.unpack('<Q', f.read(8))[0]
    assert image_base == IMAGE_BASE, \
        f"ImageBase mismatch: PE header says 0x{image_base:x}, IMAGE_BASE={IMAGE_BASE:#x}"

    # ── KNOWN_VAS sanity: all VAs must land in a valid section ─────────────────
    for name, va in KNOWN_VAS.items():
        assert IMAGE_BASE < va < IMAGE_BASE + 0x20000000, \
            f"KNOWN_VAS[{name!r}] = 0x{va:x} is outside expected range"

    # ── Oracle checks ──────────────────────────────────────────────────────────
    if _HAS_VERIFY:
        assert not verify(b'\x00'*16, b'\x00'*16), \
            "NEGATIVE: null key+iv must not pass oracle"
        assert not verify(b'\x01'*16, b'\x02'*16), \
            "NEGATIVE: random garbage must not pass oracle"
        print(f"  Oracle: _HAS_VERIFY=True, {len(_PAIRS)} known pairs loaded")
    else:
        print("  Oracle: pycryptodome not installed — verify() always returns False")

    print(f"OK: ground_truth.py verified")
    print(f"  Binary  : {os.path.basename(TARGET_DLL)} @ {IMAGE_BASE:#x}")
    print(f"  Known VAs: {len(KNOWN_VAS)}")
    print(f"  Strings  : {len(KNOWN_STRINGS)}")


if __name__ == "__main__":
    _verify()
