# Reverse Engineering Research & Taxonomy

**Goal:** learn how unfamiliar *real compiled programs* work, and turn the investigation into reusable, evidence-backed explanations. This is a research/education experiment, **not** a polished or autonomous reverse-engineering assistant.

**Status:** experimental. Different scripts belong to different investigations; do not assume the whole repository is one working pipeline. Findings and heuristics are hypotheses until independently checked.

## Start here

Do **not** try to memorize the toolkit's command set. Start with:

```
python cli.py capabilities
```

It maps an investigation question to the relevant capabilities. For LLM use, `python cli.py capabilities --json` exposes the same map in machine-readable form.

| I want to… | Start with | Why |
| --- | --- | --- |
| See what an existing analysis knows, misses, or recommends next | `python cli.py capabilities`, then `python cli.py status` / `python cli.py next 10` | Highest-level view of progress; requires prior artifacts for many functions |
| Try the dynamic classifier on a particular binary/function | `python cli.py --help`; inspect `cli.py` examples | The current classifier's command entry point; execution is platform/dependency-specific |
| Get the compact structural map for an analyzed binary | `python cli.py brief <label>` | Bounded LLM packet: overview, a few high-value targets, interpretation, and an explicit coverage boundary |
| Understand how machine-code structure is categorized | [TAXONOMY.md](TAXONOMY.md) | Function archetypes, graph motifs, limitations and investigation priorities |
| Understand the P-Code experiments | [PCODE_PIPELINE.md](PCODE_PIPELINE.md) | Lifting, clustering and corpus-level analysis |
| Investigate *stripped* binaries where names are not available | [STRIPPED_ANALYSIS_DESIGN.md](STRIPPED_ANALYSIS_DESIGN.md) | Hypotheses and proposed research, **not** a guaranteed implemented workflow |
| Browse accumulated binary-specific explanations | [briefs/](briefs/) | Per-target research briefs, not interchangeable proof of behavioral correctness |

Run commands from the repo root. Some scripts assume Windows, Ghidra, preexisting artifacts, binaries, configured paths, or other external dependencies. A missing prerequisite is **not** evidence that the technique itself failed. Read the command's header and explicit errors before proceeding. Never execute an unknown binary outside an appropriately isolated environment.

## How to investigate a binary

1. **Ask a question.** Examples: “What subsystem handles input?”, “How does dispatch work?”, “Where does state persist?”, “What changes if this input is altered?” Define the desired explanation before choosing machinery.
2. **Collect the cheapest discriminating evidence.** Start with format/imports/strings, P-Code structure, function clusters and call relationships. Use [TAXONOMY.md](TAXONOMY.md) to avoid spending analysis budget on boilerplate.
3. **Form competing interpretations.** Separate raw observations from hypotheses. Prefer an inexpensive test that distinguishes explanations over reading every function.
4. **Escalate only when necessary.** Use relevant `dynamic/` probing, `runtime_probe.py`, or memory observation for hypotheses that static evidence cannot settle. A structural similarity is not behavioral equivalence.
5. **Record what was learned.** A useful explanation says what the program appears to do, the concrete evidence, what alternatives were rejected, what remains unresolved, and the next cheapest useful question. Reuse an existing brief where appropriate; no compulsory reporting format.

**Stopping rule:** stop investigating when the question is answered to an appropriate confidence level, the next experiment is not worth its cost, or an explicit blocker has been reached. A comprehensively classified binary is not automatically an educational success.

## Where the work lives

- **Entry points:** [cli.py](cli.py) (primary operational entry point, including status/next/floors/holes and dynamic operations), [analyze.py](analyze.py) (compatibility wrapper for the analysis-orientation commands).
- **Structural evidence pipeline:** use `python cli.py brief <label>`. The internal persisted stages are `pcode_extractor.py → pcode_normalize.py → pcode_grammar.py → pcode_cluster.py → pcode_wl.py`; normally an LLM should not invoke or carry these stages individually. Use `--rebuild-corpus` only when the shared evidence substrate actually needs refreshing.
- **Static investigation:** `ghidra_run.py`, `ghidra_dump_calltree.py`, `pe_utils.py`, `elf_reader.py` and `ar_reader.py`.
- **Behavior and uncertainty:** [dynamic/](dynamic/) and `runtime_probe.py`; these are not all interchangeable implementations.
- **Accumulated evidence:** `knowledge_bus.py`, `ground_truth.py`, [briefs/](briefs/), [TAXONOMY.md](TAXONOMY.md).
- **Corpus experiments:** `corpus_*.py`, `collect_geometry.py`, `*_survey.py`, `spectral_*.py`, and related experimental scripts.
- **Quarantined investigation scripts:** [potential_deletion/](potential_deletion/) holds fifteen one-off mGBA, debugging, and naming experiments moved without modifying their contents. They are **not** active entry points. Review each for reusable evidence, overlap, or genuine obsolescence before rescue or deletion. Because some scripts assume the old root-relative imports and specific local files, relocation is not a promise that they run unchanged.
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

**Current consolidation boundary:** Keep shared modules and entry points at their existing import paths until their actual callers and runtime assumptions can be checked. Specialized capabilities do not need to disappear merely because a human would forget their commands; they do need to be cheaply rediscoverable from the question being asked. Evaluate remaining root files by whether they are (a) reusable capability, (b) evidence/educational finding, (c) independent experiment, or (d) redundant/unclear. Only the last group belongs in quarantine. Do not conflate a one-off experiment with a disposable discovery.\n\n**Milestone worth expanding for others:** on a previously unseen stripped binary, independently produce a useful, evidence-backed explanation of a nontrivial subsystem, including a successful discriminating check, with limited manual guidance. Until that is repeatable, prefer experiments and minimal maintenance over more infrastructure.
