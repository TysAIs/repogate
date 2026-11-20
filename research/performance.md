# RepoGate performance — measurements and optimization plan (Nov 20, 2026)

Scanner under test: `repogate.py` v1.2 (49 rules, 181 patterns, 6 structural
checks). All numbers measured on this VM (Python 3.12.3, 4 visible cores,
1.5 shared vCPUs). Caveat: sibling RepoGate scans (an FP-baseline batch) ran
concurrently during most measurements, so **wall times are pessimistic**;
single-thread CPU demand is the cleaner figure where given (django: 80.8s
user vs 125.6s wall on the cross-check run). Benchmark tooling lived in
/tmp/bench; the scanner was not modified.

## Benchmarks — real trees, median of 3 runs

| Tree | Files (total) | Files scanned | Size | Wall (median) | Files/s | MB/s |
|---|---|---|---|---|---|---|
| pallets/itsdangerous | 50 | 42 | 0.3 MB | **0.75s** | 67 | 0.37 |
| pallets/flask | 236 | 222 | 1.8 MB | **2.77s** | 85 | 0.65 |
| pytest-dev/pytest | 652 | 625 | 7.6 MB | **25.7s** | 25 | 0.29 |
| django/django | 7,104 | 5,742 | 46.4 MB | **131.4s** | 54 | 0.35 |

Throughput is 0.3–0.65 MB/s — two to three orders of magnitude below what
the hardware does moving bytes. The variance is content, not size: pytest
runs at 25 files/s vs django's 54 because its files are dense Python with
many string assignments (which feed the variant pipeline, below). A 7k-file
repo taking ~2 minutes is the number to fix; the pre-clone gate use case
wants this in seconds.

## Profile — cProfile on the pytest tree (625 files scanned)

Profiled run 29.9s (unprofiled 25.7s). `apply_rules` cumulative time is
27.9s = **93% of the entire scan**. Inside it:

| # | Sink | Evidence | Share |
|---|---|---|---|
| 1 | **Rule×pattern×variant `re.search` loop** | 275,785 `re.Pattern.search` calls, 15.46s tottime; **~441 searches per scanned file**. Plus 274,881 `re._compile` calls — patterns are passed as strings and re-looked-up in the re cache on every search (~0.5–1s of wrapper/compile overhead) | 52% tottime |
| 2 | **`decode_tags_block` per-character Python loop** | 766 calls, 4.83s tottime + 3.37s in 12.49M `ord()` calls = 8.2s cumulative; parent `decoded_variants` cum 9.07s. It walks every character of every base text hunting Unicode Tags-block chars | 27% cumulative |
| 3 | **Variant construction** (`normalize` + `const_propagate`) | Unprofiled phase timing over the tree: normalize 0.36s, const_propagate 2.21s, decoded_variants 2.18s = **4.75s ≈ 19% of wall** before rules run. `const_propagate` does one full-text `re.sub` per string variable; `normalize` does up to 6 full-text `STR_CONCAT.sub` passes (`re.Pattern.sub`: 1,253 calls, 1.93s profiled) | ~19% of wall |

Measured non-sinks (checked so nobody optimizes them):

- **File I/O and walking are free.** `scan_tree` self-time 0.26s; sys time
  0.15–0.8s across runs. Files are small (avg ~12KB) and page-cached.
  **mmap would buy ~nothing in Python** — the read is not the cost, and
  `str` regexes would still need a decode copy.
- **The per-line whitespace pass** costs 0.17s over 187k lines. Negligible.
- **Variants do not explode on real code**: avg 1.22 variants/file, 1.69×
  raw bytes, **zero** decoded variants and **zero** Tags-block files in 652
  real files. The cost is not variant count — it is that every variant is
  searched against every applicable pattern to prove a negative. Most
  searches exist to establish that a rule does *not* fire.

## How the fast scanners do it (and what transfers)

- **Keyword prefilter before regex (the consensus design).** gitleaks runs
  one Aho-Corasick automaton over all rules' keywords; a rule whose
  keywords are absent never runs its regex. TruffleHog routes 512-byte
  windows around keyword hits to its ~800 detectors so regexes never scan
  whole inputs. Nosey Parker (Rust) does two stages: all rules in one
  Vectorscan database, then per-rule `regex::bytes` re-match only for
  captures — GB/s-class. secretlint's Nov 2026 perf PR measured the stages
  separately on 14,430 clean files: sync walker −7%, **keyword prefilter
  −28%**, worker threads −19% more (cumulative −45%); on secret-dense
  files the prefilter gained nothing and the workers did the work.
- **ripgrep's literal stack.** Per pattern, extract required literals;
  serve them with memchr (single common byte), Teddy (SIMD multi-literal),
  or a full Aho-Corasick DFA, and only run the regex engine on candidate
  regions. Parallelism is a work-stealing tree walk (the `ignore` crate).
  The Rust `regex` crate does this literal extraction *automatically* —
  a structural advantage Python `re` does not have.
- **Aho-Corasick from Python is cheap to run.** Micro-benchmark on our
  corpus: one pyahocorasick pass (265 keywords crudely harvested from the
  actual rule patterns) over all 652 pytest files took **0.79s total
  (1.2ms/file, 9.5MB/s)** vs ~20s spent in the rule-search loop — the pass
  costs ~4% of what it routes. Caveat measured too: the crude keyword set
  produced 52,668 hits (avg 81/file) — promiscuous keywords (`http`,
  `com`) route too much. Gitleaks' keywords are curated per rule; the
  skip rate, not the pass cost, is the design variable.
- **Vectorscan/Hyperscan** compiles thousands of patterns into one SIMD
  automaton (multi-GB/s). It is the endgame if the ruleset grows to the
  ~450+ merged packs of SYNTHESIS phase 1–2 — at 49 rules, plain
  Aho-Corasick routing captures nearly all of the win without a C++
  dependency and a non-portable build.
- **Content-hash incremental caching** is a solved pattern (SHA-256 per
  file; invalidate on content, ruleset, or scanner-version change;
  near-instant re-scans in monorepos). It fits RepoGate unusually well:
  SYNTHESIS already separates scan (pure function of content → per-file
  Findings IR) from gate, and every post-pass (context demotion, chains,
  scoring) operates on the merged finding set — so cached per-file
  findings can be re-merged and re-gated exactly, with only changed
  files re-scanned.

## Ranked optimization plan

### Python — now (single file; stdlib-purity noted per item)

1. **Guard `decode_tags_block` with a C-speed precondition.** One compiled
   regex search for `[\U000E0000-\U000E007F]`; run the Python loop only on
   a hit. Micro-benchmark: 0.13s vs 1.02s per medium tree (8×), and it
   removes ~27% of profiled time. *Cost: ~5 lines. Risk: none — same
   outputs.* Expected: medium 25.7s → ~23.5s; more on doc-heavy trees.
2. **Precompile every pattern once; pre-group rules by extension/path.**
   Kills 274,881 per-search `_compile` cache lookups and the per-file
   rule-filter scan. *Cost: an hour. Risk: none.* Expected: −5–10%.
3. **Keyword prefilter (the big one).** Add curated `keywords` to each
   rule (they belong in the RRF rule-pack format anyway, as data). Per
   file, compute the present-keyword set once per variant, run only
   routed rules; rules without keywords always run. Implementation
   options in order of preference: (a) pyahocorasick/ahocorasick_rs when
   importable (C speed; ahocorasick_rs measured 4–7× pyahocorasick on
   many-pattern workloads) — but this breaks the zero-dependency rule,
   so it must be an optional accelerator; (b) stdlib fallback: one
   C-speed tokenization pass (`re.finditer` over identifier tokens) +
   set intersection — approximates AC for the identifier-shaped keywords
   most rules use; (c) no prefilter. *Cost: 1–2 days including keyword
   curation and a parity test (prefiltered scan must produce identical
   findings on the eval corpus). Risk: a bad keyword silently disables a
   rule — the parity test is the mitigation, and it is mandatory.*
   Expected: eliminate 60–85% of pattern searches on typical clean code
   → **2–3.5× end-to-end**. (Finding-dense trees gain less; see
   secretlint's staged numbers.)
4. **Cheap gates on variant construction.** Skip `normalize` when the
   text contains no quote-plus adjacency; replace `const_propagate`'s
   per-variable `re.sub` loop with one combined substitution pass.
   *Cost: half a day. Risk: low, covered by the evasion fixtures.*
   Expected: variant pipeline 19% → ~7% of wall (−10–12% overall).
5. **Multiprocess file parallelism.** `ProcessPoolExecutor` over file
   shards; merge `ScanResult`s (findings are per-file until the post
   passes, which already run once over the merged set). The workload is
   single-core CPU-bound (user ≈ 88% of wall unprofiled), so this scales
   with cores: **2.5–3.5× on a quiet 4-core host**. *Cost: 1–2 days
   (deterministic merge ordering, per-worker temp dirs for nested
   archives). Do after 1–4 — it multiplies whatever per-file cost
   remains.*
6. **Content-hash incremental cache.** Key: SHA-256(content) + ruleset
   hash + scanner version → per-file findings, stored in
   `~/.cache/repogate/`. Re-run context/chains/scoring over the merged
   set every time (cheap, exact). *Cost: 2–3 days with invalidation
   tests.* Expected: **django re-scan 131s → ~2–3s at 1% churn**
   (hashing 46MB is <0.5s); the CI/pre-commit shape benefits most.
   First scans unchanged.

Modeled Python end-state (items 1–5, assumptions above): pytest
25.7s → **~2–4s**; django 131s → **~10–15s**; incremental re-scans ~2–3s
regardless of tree size. Projections, not measurements — each item
lands with its own before/after benchmark on these same trees.

### Rust — later (the SYNTHESIS step-7 engine)

Everything above is designed to carry over, because the expensive ideas
are data and architecture, not Python tricks:

- **Keywords are rule-pack data** (RRF) — the same curated anchors feed
  the Rust `aho-corasick` crate (gitleaks' exact shape) or a
  `regex::RegexSet` one-pass shortlist. The parity corpus built for the
  Python prefilter becomes the differential-test corpus for the port.
- **The `regex` crate's built-in literal extraction** (memchr/Teddy
  prefilters per pattern) is free in Rust — item 3's routing plus
  ripgrep's per-pattern stack, no hand-rolled equivalent needed.
- **Parallelism**: `ignore::WalkParallel` / rayon work-stealing, the
  ripgrep pattern; near-linear to cores, no GIL, no process-merge
  ceremony.
- **mmap finally pays**: `memmap2` + `regex::bytes` is zero-copy in
  Rust (ripgrep's Searcher decides mmap vs read by file size/policy).
  In Python it was measured pointless; in Rust it is the default fast
  path for large files.
- **Vectorscan stays optional**: justified only if the merged ruleset
  (450+ packs) makes AC routing the bottleneck; Nosey Parker is the
  reference two-stage design. It costs a C++ vendored build and
  x86_64/ARM SIMD assumptions — defer until rule count forces it.
- **The incremental cache design is language-identical** (content hash →
  Findings IR); if the cache ships in Python first, the Rust engine
  reads the same cache format.
- Anchor for the end-state: the earlier Rust spike walked + matched 16
  patterns over 1,550 files in 2.7s vs the Python full scanner's 29.2s
  (different scope — hot loop only). A full-parity Rust engine with AC
  routing + rayon should land django-class trees in the **~2–5s** range;
  that is a projection to be proven by the SYNTHESIS differential tests,
  not a promise.

## Bottom line

RepoGate v1.2 spends 93% of its time inside `apply_rules`, and most of
that proving negatives: 441 regex searches per file, a per-character
Python loop hunting characters that appear in 0 of 652 real files, and a
variant pipeline that costs ~19% before detection starts. None of the
top three sinks is I/O. The fixes are the field's standard ones —
prefilter, precompile, parallelize, cache — sequenced so each lands
with a parity test, and every one of them is designed to survive the
Rust port as data or architecture rather than being thrown away.
