"""
Extract CWEs relevant to native binary RE from the full catalog.

Filters: C or C++ applicable, excludes web/network/protocol-only weaknesses.
Output: compact list for lateral-thinking reframing exercise.

Usage: py -3.13 extract_relevant.py [--category MEM|CTRL|TYPE|ARITH|INIT|CALL]
"""
import xml.etree.ElementTree as ET
import sys, re, argparse

NS = "http://cwe.mitre.org/cwe-7"

def tag(name):
    return f"{{{NS}}}{name}"

def text_of(el, path):
    parts = path.split("/")
    cur = el
    for p in parts:
        cur = cur.find(tag(p))
        if cur is None:
            return ""
    return (cur.text or "").strip()

def is_native_code(weakness):
    """True if CWE applies to C, C++, or Assembly — not purely web/network."""
    platforms = weakness.find(tag("Applicable_Platforms"))
    if platforms is None:
        return False
    langs = platforms.findall(tag("Language"))
    lang_names = {l.get("Name","") for l in langs}
    lang_classes = {l.get("Class","") for l in langs}
    techs = platforms.findall(tag("Technology"))
    tech_classes = {t.get("Class","") for t in techs}

    native_langs = {"C", "C++", "Assembly"}
    if not lang_names & native_langs and "Language-Independent" not in lang_classes:
        return False

    # Exclude if only web-based technology
    if tech_classes == {"Web Based"} or tech_classes == {"Web Server"}:
        return False

    return True

def get_description(weakness):
    desc = text_of(weakness, "Description")
    # Truncate at first sentence
    m = re.search(r'[.!?]', desc)
    return desc[:m.end()].strip() if m else desc[:120].strip()

def get_consequences(weakness):
    cons = weakness.find(tag("Common_Consequences"))
    if cons is None:
        return []
    scopes = []
    for c in cons.findall(tag("Consequence")):
        for s in c.findall(tag("Scope")):
            if s.text:
                scopes.append(s.text.strip())
    return list(dict.fromkeys(scopes))  # deduplicated

# Rough heuristic mapping from name/description keywords → binary info structure
INFO_STRUCTURE_HINTS = {
    "MEM":  ["buffer", "overflow", "heap", "stack", "alloc", "free", "memory",
              "pointer", "null", "deref", "dangling", "out-of-bounds", "write",
              "read", "address", "bounds"],
    "FLOW": ["control", "branch", "loop", "goto", "recursion", "exception",
             "return", "exit", "unreach", "dead code", "infinite"],
    "TYPE": ["type", "cast", "confusion", "coercion", "conversion", "integer",
             "sign", "truncat", "overflow", "underflow", "wrap"],
    "CALL": ["argument", "parameter", "calling", "convention", "stack frame",
              "return value", "format string", "variadic", "uninitialized"],
    "INIT": ["uninitializ", "default", "initialization", "cleanup", "destroy",
             "resource", "leak", "close", "release"],
    "SYNC": ["race", "concurrent", "thread", "lock", "mutex", "atomic",
             "TOCTOU", "time-of-check", "shared"],
}

def classify_info_structure(name, desc):
    text = (name + " " + desc).lower()
    scores = {}
    for cat, keywords in INFO_STRUCTURE_HINTS.items():
        scores[cat] = sum(1 for kw in keywords if kw.lower() in text)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "OTHER"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", default=None,
                    help="Filter by info structure: MEM FLOW TYPE CALL INIT SYNC OTHER")
    ap.add_argument("--search", default=None, help="Keyword search in name/description")
    ap.add_argument("--max", type=int, default=0, help="Max results (0=all)")
    opts = ap.parse_args()

    print("Parsing CWE catalog...", file=sys.stderr)
    tree = ET.parse("CWE/cwec_v4.20.xml")
    root = tree.getroot()
    weaknesses_el = root.find(tag("Weaknesses"))

    results = []
    for w in weaknesses_el.findall(tag("Weakness")):
        if not is_native_code(w):
            continue
        cwe_id   = w.get("ID", "?")
        name     = w.get("Name", "")
        desc     = get_description(w)
        conseq   = get_consequences(w)
        abstract = w.get("Abstraction", "")
        struct   = classify_info_structure(name, desc)

        if opts.category and struct != opts.category:
            continue
        if opts.search:
            kw = opts.search.lower()
            if kw not in name.lower() and kw not in desc.lower():
                continue

        results.append((cwe_id, name, desc, struct, abstract, conseq))

    results.sort(key=lambda x: (x[3], int(x[0])))

    print(f"\nFound {len(results)} native-code CWEs")
    if opts.category:
        print(f"Filtered to: {opts.category}")
    print()

    shown = 0
    current_struct = None
    for cwe_id, name, desc, struct, abstract, conseq in results:
        if struct != current_struct:
            print(f"\n{'='*70}")
            print(f"  [{struct}] — Binary info structure: {struct}")
            print(f"{'='*70}")
            current_struct = struct
        print(f"\nCWE-{cwe_id} [{abstract}]: {name}")
        print(f"  {desc}")
        if conseq:
            print(f"  Consequences: {', '.join(conseq[:3])}")
        shown += 1
        if opts.max and shown >= opts.max:
            print(f"\n... (showing {opts.max} of {len(results)}, use --max 0 for all)")
            break


if __name__ == "__main__":
    main()
