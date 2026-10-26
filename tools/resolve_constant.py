"""
resolve_constant.py — query extension tables for a numeric constant or name.

Usage:
    py -3.13 resolve_constant.py 0x202
    py -3.13 resolve_constant.py 10035
    py -3.13 resolve_constant.py AF_INET
    py -3.13 resolve_constant.py GENERIC_READ

Returns all matching labels across all loaded extension files, with family and
context (call_annotations arg position, comparison_annotations, or global_sentinels).

This is the runtime lookup tool the LLM should call when it encounters an
unrecognized numeric literal after the DOMAIN_ACTIVE TOOLKIT_NOTE fires.
"""

import os, sys, json, re

_here = os.path.dirname(os.path.abspath(__file__))


def _load_extensions():
    ext_dir = os.path.join(_here, "extensions")
    if not os.path.isdir(ext_dir):
        return []
    exts = []
    for fname in sorted(os.listdir(ext_dir)):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(ext_dir, fname), encoding="utf-8") as fh:
                    exts.append(json.load(fh))
            except Exception as e:
                print(f"[WARN] {fname}: {e}", file=sys.stderr)
    return exts


def _try_int(s):
    """Parse hex or decimal integer. Returns None on failure."""
    s = s.strip()
    try:
        return int(s, 16) if (s.startswith("0x") or s.startswith("0X")) else int(s)
    except (ValueError, TypeError):
        return None


def search_by_value(query_int, extensions):
    """Find all labels for an integer value across all extension tables."""
    results = []
    for ext in extensions:
        family = ext["family"]

        # call_annotations: {func -> {arg_idx -> {val -> label}}}
        for func_name, arg_table in ext.get("call_annotations", {}).items():
            for idx_str, val_table in arg_table.items():
                for key_str, label in val_table.items():
                    if key_str == "comment":
                        continue
                    try:
                        if int(key_str, 0) == query_int:
                            results.append({
                                "family":  family,
                                "label":   label,
                                "context": f"call_annotation: {func_name}() arg[{idx_str}]",
                            })
                    except (ValueError, TypeError):
                        pass

        # comparison_annotations: {val -> label}
        for key_str, label in ext.get("comparison_annotations", {}).items():
            if key_str == "comment":
                continue
            try:
                if int(key_str, 0) == query_int:
                    results.append({
                        "family":  family,
                        "label":   label,
                        "context": "comparison_annotation (== / != pattern)",
                    })
            except (ValueError, TypeError):
                pass

        # global_sentinels: {val -> label}
        for key_str, label in ext.get("global_sentinels", {}).items():
            if key_str == "comment":
                continue
            try:
                if int(key_str, 0) == query_int:
                    results.append({
                        "family":  family,
                        "label":   label,
                        "context": "global_sentinel (unambiguous; appears anywhere)",
                    })
            except (ValueError, TypeError):
                pass

    return results


def search_by_name(query_name, extensions):
    """Find all entries where the label matches query_name (case-insensitive substring)."""
    q = query_name.lower()
    results = []
    for ext in extensions:
        family = ext["family"]

        for func_name, arg_table in ext.get("call_annotations", {}).items():
            for idx_str, val_table in arg_table.items():
                for key_str, label in val_table.items():
                    if key_str == "comment":
                        continue
                    if q in label.lower():
                        results.append({
                            "family":  family,
                            "value":   key_str,
                            "label":   label,
                            "context": f"call_annotation: {func_name}() arg[{idx_str}]",
                        })

        for key_str, label in ext.get("comparison_annotations", {}).items():
            if key_str == "comment":
                continue
            if q in label.lower():
                results.append({
                    "family":  family,
                    "value":   key_str,
                    "label":   label,
                    "context": "comparison_annotation",
                })

        for key_str, label in ext.get("global_sentinels", {}).items():
            if key_str == "comment":
                continue
            if q in label.lower():
                results.append({
                    "family":  family,
                    "value":   key_str,
                    "label":   label,
                    "context": "global_sentinel",
                })

    return results


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    query = sys.argv[1].strip()
    extensions = _load_extensions()
    if not extensions:
        print("No extension files found in extensions/.")
        sys.exit(1)

    val = _try_int(query)

    if val is not None:
        results = search_by_value(val, extensions)
        if not results:
            print(f"No match for {query} (={val:#x}) in any extension.")
            sys.exit(0)
        print(f"{query}  ({val:#x} = {val}):")
        seen = set()
        for r in results:
            key = (r["family"], r["label"], r["context"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{r['family']}]  {r['label']}")
            print(f"          context: {r['context']}")
    else:
        results = search_by_name(query, extensions)
        if not results:
            print(f"No match for name '{query}' in any extension.")
            sys.exit(0)
        print(f"Name search: '{query}'")
        seen = set()
        for r in results:
            key = (r["family"], r["value"], r["label"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{r['family']}]  {r['value']} = {r['label']}")
            print(f"          context: {r['context']}")


if __name__ == "__main__":
    main()
