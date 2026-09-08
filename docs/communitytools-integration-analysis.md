# Integration Analysis: `transilienceai/communitytools` → Erlik 2.0

**Date**: 2026-06-30
**Author**: AI coding session (analysis only — no code changes)
**Source**: <https://github.com/transilienceai/communitytools> (MIT licensed)
**Status**: Proposal for review. Each integration below should become its own Linear
story (team **UMA**) and go through the Spec Kit flow before any code lands.

---

## 1. What the upstream project is

`communitytools` is the **AI-only sibling** of Erlik — same domain (autonomous web
pentesting driven by Claude), opposite architecture. It is a pure **Claude Code skills**
package: ~230 markdown files, no orchestrator backend, no host allow-list. The agent is
assumed to be **pre-authorized** and runs fully autonomously.

Their headline result ([`papers/practice-makes-perfect.md`](https://github.com/transilienceai/communitytools/blob/main/papers/practice-makes-perfect.md)):
**100% (104/104) on a published CTF benchmark with no fine-tuning** — achieved by a loop
run ~15 times: *run benchmark → diagnose the single missing technique → write it into a
general-purpose skill file → re-run*. The same skills transfer across models
(Sonnet 4.6 → 96.2%, Haiku 4.5 → 62.5%), with a threshold finding: skill augmentation
only helps models that already clear ~80% of challenges.

### Architecture contrast

| Dimension | communitytools | Erlik 2.0 |
|---|---|---|
| Engine | Pure skills (markdown), spawned agents | Two-tier: deterministic WSTG playbooks + AI research layer over FastAPI |
| Safety floor | "user pre-authorized", autonomous, **no scope guard** | **Scope guard / host allow-list is non-negotiable** (Constitution §I) |
| Finding confidence | Blind validators + skeptic + 3× reproduce | Confidence tiers (Confirmed/Likely/Suspected) + explicit basis (§IV) |
| Audit | Append-only `experiments.md` ledger | Unified replayable `actions` table, actor-tagged (§V) |
| Proof of quality | 100% on CTF benchmark suite | Reproducible test cases mapped to WSTG IDs (§VI) |
| Process | ad-hoc skill refinement | Spec-Driven Development (Spec Kit + constitution) |

**Takeaway:** their strength is a deep, battle-tested *technique library* and a *validation
discipline that suppresses false positives*. Erlik's strength is the *deterministic-first,
scope-guarded, auditable* design. The integrations below import the former **without**
weakening the latter. Their autonomous coordinator (which explicitly forbids asking the
user and has no allow-list) is **not** portable to Erlik and is excluded from scope.

---

## 2. Relevant upstream components

- `skills/<class>/SKILL.md` (≤150 lines) + `reference/*.md` (≤200 lines) — compressed
  cheat-sheets: escalation ladders, bypass matrices, decision trees. 20 vuln/recon/
  specialty categories, OWASP Top 10 + LLM Top 10. ~160 reference files.
- `skills/coordination/` — coordinator / executor / **skeptic** / **blind-validator**
  role definitions and the experiment-ledger discipline.
- `skills/skill-update`, `skills/skill-prune` — tooling that enforces line limits and
  **behavioral triggers instead of benchmark-specific answers** (the anti-overfitting guard).
- `benchmarks/` — adapters for cybench, xbow, bountybench (`_shared/` runner, result IO,
  CWE→skill maps).
- `mcp/transilience-vuln/server.py` + `tools/nvd-lookup.py` — CVE → CVSS/CWE enrichment.

---

## 3. Integration plan (all four approved directions)

Each is scoped to land behind Erlik's existing safety boundary. File targets reference the
structure in [`specs/002-ai-research-engine/plan.md`](../specs/002-ai-research-engine/plan.md).

### 3.1 Harvest the technique/payload reference library
**Value: highest · Risk: low · Constitution: §I, §II, §VIII**

Adapt the MIT-licensed `reference/*.md` files into a knowledge base the **AI research tier**
(`orchestrator/research/evaluator.py`) consults when forming hypotheses and follow-up
actions. These are *technique descriptions*, not executors — they inform what the AI tries;
every resulting target-touching action still routes through `testcase/scope.py` and the
`actions` audit writer.

- **Where**: new `orchestrator/research/techniques/` (or `references/`) tree, loaded by
  `evaluator.py`. Keep upstream's ≤150/≤200-line discipline.
- **Guardrails**: content is advisory only; no payload file may bypass the scope guard.
  Carry MITRE/CWE/WSTG tags so harvested techniques map onto Erlik's methodology (§VI).
- **License**: MIT — retain attribution + a `PROVENANCE.md` noting the upstream commit.
- **Risk to manage**: upstream skews toward classes their benchmark exposed (e.g. SQL filter
  bypass) and lighter on others (e.g. OAuth) — don't treat coverage as uniform.

### 3.2 Adopt the validator / skeptic discipline
**Value: high · Risk: low · Constitution: §IV, §V**

Port the *patterns*, not the autonomous coordinator:
- **Blind finding-validator** — sees evidence only (no hypothesis), confirms independently.
- **Skeptic checkpoints** — periodic adversarial review to kill plausible-but-wrong leads.
- **3× reproduce before "Confirmed"** — becomes the explicit *basis* rule for the
  `Confirmed` confidence tier; `Likely`/`Suspected` map to weaker bases.

- **Where**: `orchestrator/research/` (a validator/skeptic step) + the confidence/basis
  logic in `models.py`. Wire verdicts into the `actions` audit trail.
- **Why it fits**: this is a concrete recipe for the false-positive suppression that
  §IV already demands ("a finding requires deterministic tool evidence").

### 3.3 Benchmark harness for the AI tier
**Value: high · Risk: medium · Constitution: §VI, SC-001**

Bring in a cybench/xbow/bountybench-style harness as a **regression + quality suite** that
measures whether the AI tier actually improves over time — the upstream "run → diagnose →
write skill → re-run" loop, but bounded by Erlik's research budget and scope guard.

- **Where**: new top-level `benchmarks/` (mirror upstream `_shared/` runner shape) or under
  `tests/`. Must run network-free / against intentionally-vulnerable targets only, inside
  the sandboxed Docker network — never the host.
- **Caution**: keep benchmark targets out of the default scope allow-list; a benchmark run
  is an explicit, isolated engagement.

### 3.4 CVE enrichment MCP
**Value: medium · Risk: low · Constitution: §VIII**

Wire `transilience-vuln` MCP / `nvd-lookup.py` behind Erlik's pluggable-tool abstraction so
any `CVE-YYYY-NNNNN` seen during a run is enriched with authoritative CVSS/CWE before it
influences a finding's severity.

- **Where**: `orchestrator/tool_executor.py` / the pluggable tool registry; results feed
  finding severity + basis.
- **Guardrail**: enrichment is a read-only lookup against NVD — no target contact, but still
  recorded in the audit trail for reproducibility.

---

## 4. What we explicitly do NOT take

- The **autonomous coordinator** that forbids `AskUserQuestion` and roams without an
  allow-list. Erlik's scope guard is the floor; nothing imported may weaken it (§I, Hard Gate 1).
- Their **all-AI, no-deterministic-tier** model. Erlik's deterministic playbook-first design
  is the differentiator and the thesis story.

---

## 5. Proposed sequencing (each → its own UMA story → Spec Kit flow)

1. **3.1 Technique library harvest** — unlocks the most AI-tier capability, lowest risk.
2. **3.2 Validator/skeptic discipline** — hardens findings as the library widens what the AI attempts.
3. **3.3 Benchmark harness** — lets us *measure* 3.1 + 3.2 and run the refinement loop.
4. **3.4 CVE enrichment** — independent, can land any time.

Stories 3.1–3.3 touch the AI tier and finding/confidence logic; any change near
`testcase/scope.py` or tool execution requires the §I scope-guard regression tests and human
review (Hard Gates 1–3). No story self-merges; a human moves the issue to Done.

---

## 6. Open questions for the developer

- **Vendoring vs. submodule** for the harvested references — copy (with provenance) or pull
  via a pinned upstream commit? Copy is simpler for thesis reproducibility.
- **Benchmark targets** — reuse JuiceShop / existing intentionally-vulnerable targets, or
  stand up the upstream benchmark containers in the isolated network?
- **Skeptic cadence** — upstream fires at experiments 5/15/25; Erlik's research budget is
  ~20 actions by default, so cadence needs retuning (e.g. at 1/3 and 2/3 of budget).
