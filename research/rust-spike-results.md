# Rust spike — measured results (Nov 20, 2026)

Spike scope: tree walk + 16 representative regex rules (walkdir + regex
crates, release, LTO, stripped), compared with the Python v1.1 full scanner
on the same local tree (NOMARJ/sigil clone, ~1,550 text files).

- **Binary size: 1.88 MB** stripped (regex + walkdir only). The full build
  (yara-x, tree-sitter, HTTP) will be larger; the research brief's 10–25 MB
  estimate stands as the budget, and the spike shows the floor is low.
- **Hot-loop speed: 2.7s vs Python's 29.2s** wall on the same tree (~10x).
  Honest scope note: the spike runs 16 patterns with no normalization,
  structural checks, chains, or scoring — it measures the walk+match loop
  that Rust would own in the hybrid design, not full parity. Full-parity
  speed is a differential-testing question for the migration phases.
- Toolchain: rustc/cargo 1.99.1. Build from clean: ~31s.
- Per-rule hits on the sigil tree were sane (its own pattern strings trip
  exec/cred rules, as expected for a scanner corpus).

Verdict support: the hybrid-converging-on-Rust plan in docs/SYNTHESIS-v2.md
is feasible on size and speed evidence, not just ecosystem argument.
