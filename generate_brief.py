"""
generate_brief.py — Generate a Markdown structural brief for any analyzed binary.

The brief is the LLM's entry point for autonomous binary exploration. It provides:
  - What the binary IS (domain fingerprint, archetype distribution)
  - What the LLM should EXPLORE FIRST (functions ordered by grammar coverage)
  - What PATTERNS exist (grammar rules, WL-2 design patterns)
  - What the STRUCTS look like (if struct_recover has been run)

Usage:
  py -3.13 generate_brief.py <dll_label>            # e.g. advapi32, linux_x264
  py -3.13 generate_brief.py --list                 # list all available labels
  py -3.13 generate_brief.py advapi32 --out brief.md

The brief assumes the pipeline has been run:
  pcode_extractor.py → pcode_normalize.py → pcode_grammar.py → pcode_cluster.py → pcode_wl.py

All inputs are pre-computed. Brief generation takes <5 seconds per binary.
"""
import json, sys, argparse, math, re
import numpy as np
from collections import Counter, defaultdict
from pathlib import Path

# ── Utility function detection ────────────────────────────────────────────────
# Hypothesis: CALLER/REGISTER_HEAVY + small size + low coverage = infrastructure
# wrapper with unusual calling pattern (TLS, SEH, ABI glue) — NOT novel domain code.
#
# Evidence from briefs:
#   vcruntime140: _purecall, __uncaught_exception, _controlfp all CALLER + tiny + low cov
#   x264: adl_malloc_wrapper (CALLER + tiny)
#   ntdll: MicrosoftTelemetryAssertTriggeredUM, RtlBarrierForDelete
#
# Three signals, any two = utility-suspect:
#   (1) Archetype: CALLER or REGISTER_HEAVY (delegates or shuffles registers)
#   (2) Size: < 48 bytes (< 12 instructions — too small for domain logic)
#   (3) Name pattern: known utility vocabulary (when symbols available)
#
# This is a testable hypothesis — see the brief's "Infrastructure Functions" section.

UTILITY_ARCHETYPES = {'CALLER', 'REGISTER_HEAVY'}
UTILITY_SIZE_THRESHOLD = 48   # bytes

UTILITY_NAME_PATTERNS = re.compile(
    r'(?i)(malloc|free|alloc|realloc|wrapper|stub|trampoline|telemetry|'
    r'log(ging)?|trace|assert|fail_?fast|pure_?call|uncaught|exception_?context|'
    r'unexpected|controlfp|barrier|purecall|_get_|_set_|__current_|__processing_)',
    re.IGNORECASE
)

# ── Archetype descriptions ────────────────────────────────────────────────────
ARCHETYPE_DESC = {
    'CALLER':          'Sets up stack frame and delegates to another function. Low information value — skip unless entry point.',
    'READER':          'Reads struct/array fields. Access pattern reveals data layout and field types.',
    'WRITER':          'Writes struct/array fields. Combined with READER: identifies mutable state.',
    'GETTER':          'Loads a field and returns it directly. Accessor function — reveals field semantics.',
    'GUARD_SIMPLE':    'Single conditional check at entry. Must satisfy one condition to proceed.',
    'GUARD_COMPOUND':  'Multiple conditions (BOOL_AND/OR) at entry. Policy or permission validation.',
    'REGISTER_HEAVY':  'Many register shuffles, COPY chains. ABI glue, vtable dispatch, or forwarding stub.',
    'SIMD_COPY':       'Bulk 16-byte memory operations. Struct initialization or bulk data copy.',
    'ARITHMETIC':      'Integer computation without significant memory access. Pure algorithm.',
    'FLOAT_COMPUTE':   'Floating-point operations. Signal processing, physics, graphics math.',
    'MIXED':           'No single dominant pattern. Complex function — worth LLM attention.',
    'NOISE':           'No cluster match. Structurally unusual — highest LLM exploration priority.',
}

DOMAIN_FINGERPRINTS = {
    'high_guard':    ('Validation-heavy (security/policy enforcer)',
                      'High GUARD fraction → validates inputs before every operation. Security-critical code.'),
    'high_getter':   ('Accessor-dominated (data layer or API wrapper)',
                      'High GETTER fraction → thin accessor functions. Likely a data model or abstraction layer.'),
    'high_caller':   ('Dispatch-heavy (orchestration or middleware)',
                      'High CALLER fraction → delegates most work. Orchestration or middleware layer.'),
    'high_writer':   ('State-mutation heavy (initialization or configuration)',
                      'High WRITER fraction → sets struct fields. Initialization, configuration, or serialization.'),
    'high_mixed':    ('Complex logic (algorithm implementation)',
                      'High MIXED fraction → diverse computation. Core algorithm or domain logic.'),
    'high_isolated': ('Statically opaque (computed dispatch dominant)',
                      'High isolation → heavy use of function pointers/vtables. Emulator, interpreter, or plugin system.'),
    'high_arithmetic':('Computation-dominant (codec or numerical)',
                       'High ARITHMETIC fraction → pure computation. Codec, physics, compression.'),
}


def load_data():
    """Load all pre-computed analysis results."""
    data = {}

    # Cluster assignments
    with open('pcode_clusters.json') as f:
        cl = json.load(f)
    data['fn_names']      = cl['fn_names']
    data['dll_labels']    = cl['dll']
    data['cluster_ids']   = cl['cluster']
    data['cluster_labels']= cl['cluster_labels']   # {str(id): label_str}

    # WL labels
    with open('pcode_wl.json') as f:
        wl = json.load(f)
    data['wl'] = wl

    # Grammar coverage (rule-usage vectors)
    npz = np.load('pcode_grammar_norm.npz', allow_pickle=True)
    data['rule_matrix']  = npz['rule_matrix']
    data['rule_labels']  = npz['rule_labels']
    data['gram_labels']  = npz['labels']
    data['gram_fnames']  = npz['fn_names']

    # Token sequences (for entropy + top tokens) — also carries function size
    corpus = {}
    fn_sizes = {}   # fn_key → size in bytes
    with open('pcode_corpus_norm.jsonl') as f:
        for line in f:
            rec = json.loads(line)
            key = f"{rec['dll']}::{rec['fn']}"
            corpus[key] = rec
            fn_sizes[key] = rec.get('size', 9999)
    data['corpus']   = corpus
    data['fn_sizes'] = fn_sizes

    return data


def is_utility_suspect(fn_key, fn_name, archetype, coverage, data):
    """
    Test hypothesis: CALLER/REGISTER_HEAVY + small + low coverage = utility infrastructure.
    Returns True if at least 2 of 3 signals fire.
    """
    signals = 0
    # Signal 1: archetype
    if archetype in UTILITY_ARCHETYPES:
        signals += 1
    # Signal 2: function size
    size = data['fn_sizes'].get(fn_key, 9999)
    if size < UTILITY_SIZE_THRESHOLD:
        signals += 1
    # Signal 3: name pattern (only meaningful when symbols available)
    if fn_name and not fn_name.startswith('FUN_') and UTILITY_NAME_PATTERNS.search(fn_name):
        signals += 1
    return signals >= 2


def get_dll_functions(data, label):
    """Return all function records for a given DLL label."""
    fns = []
    for i, (fn_name, dll) in enumerate(zip(data['fn_names'], data['dll_labels'])):
        if dll == label:
            short = fn_name.split('::')[-1]
            archetype = data['cluster_labels'].get(
                str(data['cluster_ids'][i]),
                'NOISE' if data['cluster_ids'][i] == -1 else f"C{data['cluster_ids'][i]}"
            )
            fns.append({
                'fn_key':       fn_name,
                'fn_name':      short,
                'cluster_id':   data['cluster_ids'][i],
                'cluster_label': archetype,
            })
    return fns


def compute_coverage(data, label):
    """Compute grammar coverage per function for this DLL."""
    mask = data['gram_labels'] == label
    if not mask.any():
        return {}, 0.0

    matrix  = data['rule_matrix'][mask].astype(float)
    fnames  = data['gram_fnames'][mask]
    coverage = matrix.mean(axis=1)

    cov_map = {}
    for fn_name, cov in zip(fnames, coverage):
        short = fn_name.split('::')[-1]
        cov_map[short] = float(cov)

    return cov_map, float(coverage.mean())


def compute_wl_patterns(data, label):
    """Get WL-2 design pattern distribution for this DLL."""
    wl2_counts = Counter()
    isolation_count = 0
    total = 0

    for fn_key, fn_data in data['wl'].items():
        if fn_data.get('dll') == label:
            total += 1
            if fn_data.get('isolated'):
                isolation_count += 1
            wl2 = fn_data.get('wl1')   # WL-1 = direct callee context
            if wl2:
                wl2_counts[fn_data.get('wl0', 'UNKNOWN')] += 1

    isolation_pct = isolation_count / total * 100 if total > 0 else 0
    return wl2_counts, isolation_pct, total


def infer_domain(archetype_dist, isolation_pct):
    """Heuristic domain fingerprint from archetype distribution."""
    total = sum(archetype_dist.values())
    if total == 0:
        return None, None

    fracs = {k: v/total for k, v in archetype_dist.items()}
    guard_frac    = fracs.get('GUARD_SIMPLE', 0) + fracs.get('GUARD_COMPOUND', 0)
    getter_frac   = fracs.get('GETTER', 0)
    caller_frac   = fracs.get('CALLER', 0)
    writer_frac   = fracs.get('WRITER', 0)
    arith_frac    = fracs.get('ARITHMETIC', 0) + fracs.get('FLOAT_COMPUTE', 0)
    mixed_frac    = fracs.get('MIXED', 0)

    if isolation_pct > 40:
        return DOMAIN_FINGERPRINTS['high_isolated']
    if arith_frac > 0.20:
        return DOMAIN_FINGERPRINTS['high_arithmetic']
    if guard_frac > 0.30:
        return DOMAIN_FINGERPRINTS['high_guard']
    if getter_frac > 0.25:
        return DOMAIN_FINGERPRINTS['high_getter']
    if caller_frac > 0.35:
        return DOMAIN_FINGERPRINTS['high_caller']
    if writer_frac > 0.25:
        return DOMAIN_FINGERPRINTS['high_writer']
    if mixed_frac > 0.25:
        return DOMAIN_FINGERPRINTS['high_mixed']
    return None, None


def generate_brief(label: str, data: dict) -> str:
    """Generate a Markdown structural brief for one DLL label."""
    fns = get_dll_functions(data, label)
    if not fns:
        return f'# {label}\n\nNo data found. Run the pipeline first.\n'

    cov_map, mean_cov = compute_coverage(data, label)
    _, isolation_pct, wl_total = compute_wl_patterns(data, label)

    # Archetype distribution
    archetype_dist = Counter(fn['cluster_label'] for fn in fns)
    total_fns = len(fns)
    noise_count = archetype_dist.get('NOISE', 0)
    noise_pct = noise_count / total_fns * 100

    # Domain fingerprint
    domain_name, domain_desc = infer_domain(archetype_dist, isolation_pct)

    # Token entropy from corpus
    all_tokens = []
    for fn in fns:
        rec = data['corpus'].get(fn['fn_key'], {})
        all_tokens.extend(rec.get('tokens', []))
    entropy = 0.0
    if all_tokens:
        cnt = Counter(all_tokens)
        total_t = sum(cnt.values())
        entropy = -sum((c/total_t) * math.log2(c/total_t) for c in cnt.values() if c > 0)

    # Exploration priority: functions with lowest grammar coverage
    fn_coverage = []
    for fn in fns:
        cov = cov_map.get(fn['fn_name'], None)
        fn_coverage.append((fn['fn_name'], fn['cluster_label'], cov))
    fn_coverage.sort(key=lambda x: x[2] if x[2] is not None else 0)

    # Top grammar rules (most discriminating for this DLL)
    gram_mask = data['gram_labels'] == label
    if gram_mask.any():
        dll_mean = data['rule_matrix'][gram_mask].astype(float).mean(axis=0)
        global_mean = data['rule_matrix'].astype(float).mean(axis=0)
        lift = dll_mean - global_mean
        top_rule_idx = np.argsort(lift)[::-1][:6]
        top_rules = [(str(data['rule_labels'][i]), float(lift[i]), float(dll_mean[i]))
                     for i in top_rule_idx if lift[i] > 0.05]
    else:
        top_rules = []

    # ── Build Markdown ────────────────────────────────────────────────────────
    lines = []
    lines.append(f'# Structural Brief: `{label}`')
    lines.append('')
    lines.append('> Auto-generated by `generate_brief.py`. Use this as LLM exploration context.')
    lines.append('')

    # Overview
    lines.append('## Overview')
    lines.append('')
    lines.append(f'| Property | Value |')
    lines.append(f'|---|---|')
    lines.append(f'| Total functions | {total_fns:,} |')
    lines.append(f'| Grammar coverage (mean) | {mean_cov:.3f} ({_coverage_label(mean_cov)}) |')
    lines.append(f'| Token entropy | {entropy:.2f} bits |')
    lines.append(f'| Isolated nodes | {isolation_pct:.1f}% (statically opaque) |')
    lines.append(f'| Noise (unclassified) | {noise_pct:.1f}% |')
    if domain_name:
        lines.append(f'| Domain fingerprint | **{domain_name}** |')
    lines.append('')

    if domain_desc:
        lines.append(f'**{domain_desc}**')
        lines.append('')

    # Archetype distribution
    lines.append('## Structural Archetypes')
    lines.append('')
    lines.append('| Archetype | Count | % | What it means |')
    lines.append('|---|---|---|---|')
    for archetype, count in archetype_dist.most_common():
        pct = count / total_fns * 100
        desc = ARCHETYPE_DESC.get(archetype, '')
        lines.append(f'| {archetype} | {count} | {pct:.1f}% | {desc} |')
    lines.append('')

    # Exploration priority
    lines.append('## LLM Exploration Priority')
    lines.append('')
    lines.append('Functions ordered by grammar coverage (0.0 = matches no known pattern = explore first).')
    lines.append('High coverage = predictable, classify cheaply. Low coverage = novel, spend LLM budget here.')
    lines.append('')
    lines.append('### Explore First (coverage ≤ 0.15 — structurally novel domain logic)')
    lines.append('')

    novel_domain = []
    novel_utility = []
    for fn_name, cluster_label, cov in fn_coverage:
        if cov is None or cov > 0.15:
            continue
        fn_key = f'{label}::{fn_name}'
        size = data['fn_sizes'].get(fn_key, 0)
        if is_utility_suspect(fn_key, fn_name, cluster_label, cov, data):
            novel_utility.append((fn_name, cluster_label, cov, size))
        else:
            novel_domain.append((fn_name, cluster_label, cov, size))

    if novel_domain:
        # Orchestrators: largest novel functions — controllers, state machines, complex handlers
        # Sort by size desc within same coverage band to surface these first
        orchestrators = sorted(novel_domain, key=lambda x: -x[3])
        SIZE_THRESHOLD = 500  # bytes — heuristic for "large enough to be an orchestrator"
        large = [f for f in orchestrators if f[3] >= SIZE_THRESHOLD]

        if large:
            lines.append('#### Orchestrators / Controllers (large novel functions — explore these first)')
            lines.append('')
            lines.append('*Large + low coverage = complex unique logic. These likely control subsystems.*')
            lines.append('')
            lines.append('| Function | Archetype | Coverage | Size (bytes) |')
            lines.append('|---|---|---|---|')
            for fn_name, cluster_label, cov, size in large[:10]:
                lines.append(f'| `{fn_name}` | {cluster_label} | {cov:.3f} | {size:,} |')
            if len(large) > 10:
                lines.append(f'| *(+{len(large)-10} more large functions)* | | | |')
            lines.append('')
            lines.append('#### Specific Implementations (smaller novel functions)')
            lines.append('')

        # Remaining: sort by coverage asc, then size desc
        small = sorted(novel_domain, key=lambda x: (x[2], -x[3]))
        small_only = [f for f in small if f[3] < SIZE_THRESHOLD]

        lines.append('| Function | Archetype | Coverage | Size (bytes) |')
        lines.append('|---|---|---|---|')
        for fn_name, cluster_label, cov, size in small_only[:20]:
            lines.append(f'| `{fn_name}` | {cluster_label} | {cov:.3f} | {size:,} |')
        remaining = len(novel_domain) - min(len(large), 10) - min(len(small_only), 20)
        if remaining > 0:
            lines.append(f'| *(+{len(novel_domain) - min(len(large),10) - min(len(small_only),20)} more)* | | | |')
    else:
        lines.append('*All novel functions appear to be infrastructure wrappers.*')
    lines.append('')

    if novel_utility:
        lines.append('### Infrastructure Functions (low coverage but likely utility — lower priority)')
        lines.append('')
        lines.append('*Hypothesis: CALLER/REGISTER_HEAVY + size < 48 bytes + utility name = wrapper.*')
        lines.append('*The function body is trivial — but functions with many callers (★) are structural hubs.*')
        lines.append('*Backtracking WHO CALLS a hub immediately maps every code path for that concern.*')
        lines.append('')
        lines.append('| Function | Archetype | Coverage | Callers |')
        lines.append('|---|---|---|---|')
        for fn_name, cluster_label, cov, _size in novel_utility[:15]:
            fn_key = f'{label}::{fn_name}'
            n_callers = data['wl'].get(fn_key, {}).get('n_callers', 0)
            hub_marker = ' ★' if n_callers >= 5 else ''  # within-corpus callers (conservative lower bound)
            lines.append(f'| `{fn_name}` | {cluster_label} | {cov:.3f} | {n_callers}{hub_marker} |')
        if len(novel_utility) > 15:
            lines.append(f'| *(+{len(novel_utility)-15} more)* | | | |')
        lines.append('')

    lines.append('### Classify Cheaply (coverage ≥ 0.60 — highly predictable)')
    lines.append('')
    common = [(n, cl, cov) for n, cl, cov in fn_coverage if cov is not None and cov >= 0.60]
    if common:
        lines.append('| Function | Archetype | Coverage |')
        lines.append('|---|---|---|')
        for fn_name, cluster_label, cov in sorted(common, key=lambda x: -x[2])[:10]:
            lines.append(f'| `{fn_name}` | {cluster_label} | {cov:.3f} |')
    else:
        lines.append('*No functions with very high grammar coverage.*')
    lines.append('')

    # Dominant grammar patterns
    if top_rules:
        lines.append('## Dominant Grammar Patterns')
        lines.append('')
        lines.append('P-Code idioms that appear MORE in this binary than the corpus average.')
        lines.append('These are the structural "vocabulary" of this binary.')
        lines.append('')
        lines.append('| Pattern | Lift over baseline | Usage rate |')
        lines.append('|---|---|---|')
        for rule_str, lift, usage in top_rules:
            short = rule_str[:60] + ('...' if len(rule_str) > 60 else '')
            lines.append(f'| `{short}` | +{lift:.3f} | {usage:.2f} |')
        lines.append('')

    # Interpretation guide
    lines.append('## Interpretation Guide for LLM')
    lines.append('')
    lines.append('When exploring this binary:')
    lines.append('')
    if isolation_pct > 30:
        lines.append(f'- **{isolation_pct:.0f}% of functions are statically opaque** (computed dispatch, vtables). '
                     'These are the most domain-specific — start here.')
    lines.append(f'- **Grammar coverage {mean_cov:.2f}** → '
                 + ('High: most functions match known C patterns. Budget is low per function.'
                    if mean_cov > 0.35
                    else 'Low: many functions are structurally novel. Budget is high per function.'))
    lines.append(f'- **Token entropy {entropy:.2f} bits** → '
                 + ('High diversity (codec/emulator-like)' if entropy > 4.5
                    else 'Normal diversity (system library-like)' if entropy > 4.1
                    else 'Low diversity (narrow utility library)'))
    if archetype_dist.get('NOISE', 0) > total_fns * 0.10:
        lines.append(f'- **{noise_pct:.0f}% noise** → Unusually many unclassifiable functions. '
                     'This binary has high structural uniqueness vs the training corpus.')
    lines.append('')
    lines.append('---')
    lines.append('*Generated by `generate_brief.py` — part of the P-Code Structural Taxonomy pipeline.*')
    lines.append('*Corpus: 69,653 functions across 24 PE/ELF/static lib targets.*')

    return '\n'.join(lines)


def _coverage_label(cov: float) -> str:
    if cov < 0.20: return 'novel — high LLM budget'
    if cov < 0.35: return 'moderate'
    if cov < 0.50: return 'predictable'
    return 'highly predictable — low LLM budget'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('label', nargs='?', help='DLL label (e.g. advapi32, linux_x264)')
    ap.add_argument('--list', action='store_true', help='List all available labels')
    ap.add_argument('--out', help='Output file (default: stdout)')
    ap.add_argument('--all', action='store_true', help='Generate briefs for all labels')
    args = ap.parse_args()

    print('Loading analysis data...', file=sys.stderr)
    data = load_data()

    all_labels = sorted(set(data['dll_labels']))

    if args.list:
        print('Available labels:')
        for lbl in all_labels:
            cnt = sum(1 for d in data['dll_labels'] if d == lbl)
            print(f'  {lbl:<25} {cnt:>6,} functions')
        return

    if args.all:
        Path('briefs').mkdir(exist_ok=True)
        for lbl in all_labels:
            brief = generate_brief(lbl, data)
            out_path = f'briefs/{lbl}.md'
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(brief)
            print(f'  {lbl} → {out_path}')
        return

    if not args.label:
        ap.print_help()
        return

    brief = generate_brief(args.label, data)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(brief)
        print(f'Brief written to {args.out}')
    else:
        print(brief)


if __name__ == '__main__':
    main()
