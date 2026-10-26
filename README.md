# Reverse Engineering Research & Taxonomy

**Goal:** given an unfamiliar *real compiled program* and a question about it, minimize the total cost of reaching a defensible, useful understanding. The project automates cheap structural work so an LLM can spend more of its budget framing questions, comparing hypotheses, choosing discriminating evidence, updating beliefs, and explaining what matters. It is a research/education experiment, **not** a claim of a finished autonomous reverse-engineering assistant.

**Status:** experimental. Different scripts belong to different investigations; do not assume the whole repository is one working pipeline. Findings and heuristics are hypotheses until independently checked.

## Start here

Do **not** try to memorize the toolkit's command set. Start from the investigation:

```
python cli.py investigation new "How does this program dispatch work?" --target mgba \
  --stop "the dispatch mechanism is supported by discriminating evidence"
python cli.py status
python cli.py capabilities
python cli.py brief
```

The local investigation state stores only what should change future decisions: active question, parent goal, hypotheses, evidence, consequential uncertainties, next action and stopping rule. It does **not** duplicate calltrees, P-Code, pseudocode or briefs. `capabilities` maps questions to the long tail of precise mechanisms when needed.

| I want to… | Start with | Why |
| --- | --- | --- |
| Preserve the active question, hypotheses and stopping rule | `python cli.py investigation` / `python cli.py status` | Keeps the investigation question-relative across tools and sessions |
| Try the dynamic classifier on a particular binary/function | `python cli.py --help`; inspect `cli.py` examples | The current classifier's command entry point; execution is platform/dependency-specific |
| Get the compact structural map for an analyzed binary | `python cli.py brief [label]` | Bounded LLM packet: overview, structurally novel candidates, interpretation and an explicit coverage boundary; inherits the active target when possible |
| Understand how machine-code structure is categorized | [TAXONOMY.md](TAXONOMY.md) | Function archetypes, graph motifs, limitations and investigation priorities |
| Understand the P-Code experiments | [PCODE_PIPELINE.md](PCODE_PIPELINE.md) | Lifting, clustering and corpus-level analysis |
| Investigate *stripped* binaries where names are not available | [STRIPPED_ANALYSIS_DESIGN.md](STRIPPED_ANALYSIS_DESIGN.md) | Hypotheses and proposed research, **not** a guaranteed implemented workflow |
| Browse accumulated binary-specific explanations | [briefs/](briefs/) | Per-target research briefs, not interchangeable proof of behavioral correctness |

Run commands from the repo root. Some scripts assume Windows, Ghidra, preexisting artifacts, binaries, configured paths, or other external dependencies. A missing prerequisite is **not** evidence that the technique itself failed. Read the command's header and explicit errors before proceeding. Never execute an unknown binary outside an appropriately isolated environment.

## How to investigate a binary

1. **Frame the investigation.** Record the question, parent purpose, what a useful result must enable, plausible hypotheses and an explicit stopping condition. Ask another question only if its answers would materially change evidence selection or the final decision.
2. **Orient cheaply.** Use the structural brief and other deterministic summaries to understand the landscape before reading functions locally. Structural novelty estimates investigation cost/uncertainty; it is **not** semantic importance.
3. **Choose by expected value.** Filter structural candidates through the active question. Prefer evidence that most cheaply separates live hypotheses rather than accumulating observations indiscriminately.
4. **Escalate adaptively.** Move from static evidence to targeted classification/simulation, state recovery, memory or runtime observation only when the cheaper layer cannot resolve a consequential uncertainty.
5. **Update beliefs explicitly.** Record observations separately from interpretations; mark hypotheses supported, weakened or rejected rather than silently replacing them.
6. **Stop and explain.** Stop when the intended decision/understanding is supported well enough, competing hypotheses are practically equivalent, or the next experiment is not worth its cost. Preserve residual uncertainty and reopening conditions.

**Stopping rule:** stop investigating when the question is answered to an appropriate confidence level, the next experiment is not worth its cost, or an explicit blocker has been reached. A comprehensively classified binary is not automatically an educational success.

## Where the work lives

- **Operational spine:** [cli.py](cli.py) + [investigation.py](investigation.py). The question/hypotheses/stop rule govern which evidence is worth collecting.
- **Structural orientation:** `python cli.py brief [label]` is the normal surface. [structural/](structural/) contains the persisted extractor → normalizer → grammar → clustering → WL implementation and should normally remain invisible to the LLM. Use `--rebuild-corpus` only when the evidence substrate needs refreshing.
- **Structural extraction:** [structural/](structural/) contains Ghidra extraction, PE/ELF/archive readers, P-Code lifting, grammar/clustering/WL and brief generation. These are deterministic evidence-producing mechanisms beneath the `brief` surface.
- **Targeted escalation:** [dynamic/](dynamic/) contains behavioral execution, simulation, state/memory observation, vtable recovery and runtime escalation. [reasoning/](reasoning/) contains LLM semantic naming, concrete trace reasoning and understanding-hole maps. These answer specific uncertainties; they are not a mandatory pipeline.
- **Evidence:** [evidence/](evidence/) contains optional target configuration/oracles, the cross-layer knowledge bus and accumulated observation corpus. Local investigation state, [briefs/](briefs/) and [TAXONOMY.md](TAXONOMY.md) are higher-level evidence/navigation artifacts. Target-specific facts are configuration, not project architecture.
- **Research on better routing:** [research/structural_signals/](research/structural_signals/) studies geometry, convergence, GF(2), spectral and related signals; [research/validation/](research/validation/) audits whether the measurement pipeline itself is trustworthy. Research earns operational adoption only if it improves downstream decisions/understanding per cost.
- **Quarantined investigation scripts:** [potential_deletion/](potential_deletion/) holds superseded, one-off, debugging and ambiguous experiments moved without deleting their contents. They are **not** active entry points. Review each for reusable evidence, overlap, or genuine obsolescence before rescue or deletion. Because some scripts assume the old root-relative imports and specific local files, relocation is not a promise that they run unchanged.
- **Reference data:** [CWE/](CWE/) contains a large upstream CWE dataset plus utilities; it is not part of the default binary-learning loop.
- **Design history:** [STRIPPED_ANALYSIS_DESIGN.md](STRIPPED_ANALYSIS_DESIGN.md) and [PCODE_PIPELINE.md](PCODE_PIPELINE.md). Distinguish plans from demonstrated outcomes.

## Research principles

- **Question before tool.** Do not deploy a sophisticated algorithm merely because it exists.
- **Observation before assertion.** Say what an instrument measured, what you infer, and what would falsify that inference.
- **Abstain explicitly.** `unresolved` is more useful than an attractive but unverified function name.
- **Budget globally.** Static scoring and taxonomy help route scarce attention; deep dynamic analysis is only justified when it changes the answer.
- **Bound LLM context.** Persist rich intermediate evidence, but surface only the smallest structural packet likely to change the next action. Descend into the full brief, function evidence, or raw corpus on demand; do not repeatedly stuff the pipeline's internal artifacts into context.
- **Make results discoverable.** A future reader should be able to find the relevant binary, question, evidence, and next step without reconstructing the entire project's history.
- **Prioritize educational value.** A small convincing case study of an unknown binary matters more than many impressive-looking unsituated metrics.

**Consolidation criterion:** every component must improve at least one of: question framing, orientation, relevance estimation, uncertainty reduction, evidence quality, reusable learning, or investigation cost. Specialized capabilities may remain numerous for an LLM, but they must be cheaply rediscoverable and should not occupy the main operational path. Research may remain valuable without being runtime machinery. A component that produces interesting output but never changes a downstream decision, belief, stopping point or explanation has not earned operational existence.

**Milestone worth expanding for others:** on a previously unseen stripped binary, independently produce a useful, evidence-backed explanation of a nontrivial subsystem, including a successful discriminating check, with limited manual guidance. Until that is repeatable, prefer experiments and minimal maintenance over more infrastructure.
