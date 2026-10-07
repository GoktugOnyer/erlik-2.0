# Making small local models perform better — inference & orchestration levers

Status: **design / roadmap**, with one lever (`num_ctx` sizing) already shipped
and labelled as such. The goal is to raise the usable competence of a small
local model (the default is `qwen2.5-coder:7b`,
`orchestrator/llm_client.py:22`) **without fine-tuning and without new
operator setup** — only inference-time and orchestration changes.

Scope discipline (CLAUDE.md, *Thesis vs product*): every lever here is a new,
**off-by-default** flag. OFF must be an exact no-op so none of the three frozen
`TOOLSET_PRESETS` arms shifts and no recorded campaign becomes incomparable.
Flags are wired the way `orchestrator/runconfig.py` already wires tri-state
flags (`_BOOL_KEYS`, line 33; the override tuple and `_known` set in
`resolve()`, lines 164/178; the return dict, line 294).

Honesty labels used below: **shipped**, **mechanical** (clear hook, low risk,
not yet measured), **speculative** (plausible but unmeasured, and the
mechanism may not pay off on a 7B).

## Summary

| Lever | Flag | Hook | Addresses | Confidence |
|---|---|---|---|---|
| Structured JSON decoding | `structured_json` | `llm_client._ollama_chat` / `_openai_chat` | model emits prose, not a parseable action | mechanical |
| Structured error feedback (Reflexion-lite) | `reflexion` | agent loop feedback appends (`main.py`) | model repeats the same failing command | mechanical (partly shipped) |
| Dynamic phase-scoped tool menu | `phase_tool_menu` | `render_system_prompt` / `tools_str` | small model overwhelmed by a 30-tool menu | speculative |
| Few-shot action exemplars | `action_exemplars` | `render_system_prompt` | malformed/empty actions, esp. early turns | speculative |
| Turn-budget framing | `soft_turn_budget` | agent loop prompt + stagnation | model rushing to `done` or stalling | speculative |
| `num_ctx` sizing | (shipped) | `llm_client.chat(num_ctx=…)` | Ollama silently truncating the prompt | **shipped** |

## 1. Structured / constrained JSON decoding — `structured_json`

**What it does.** Forces the provider to emit syntactically valid JSON at
decode time, instead of hoping the model does and parsing defensively after.

- Ollama: add `"format": "json"` to the request body. The hook is
  `_ollama_chat`, where `options` is already assembled and attached
  (`orchestrator/llm_client.py:55-72`). `format` is a top-level field on the
  `/api/chat` body, a sibling of `options`.
- OpenAI-compatible: add `response_format={"type": "json_object"}` to the body
  in `_openai_chat` (`orchestrator/llm_client.py:211`). Honoured by the OpenAI
  API and most compatible gateways; some do not implement it, so the flag must
  degrade to today's behaviour rather than erroring (see failure mode).

**Where it hooks in.** `orchestrator/llm_client.py`, threaded through
`chat(...)` (line 350) as a new keyword, resolved from the runconfig flag by
the agent loop at the call site (`orchestrator/main.py:5086`). `chat_json`
(line 363) is a natural second caller but is not on the agent's hot path.

**Failure mode addressed.** Today the model's text is parsed post-hoc by
`_parse_llm_action` (`orchestrator/main.py:1473`): direct `json.loads`, then a
```` ```json ```` block, then a regex for any `{…"action"…}`. When all three
miss, the loop spends a whole turn on the JSON nudge
(`orchestrator/main.py:5161-5175`) — a wasted LLM round trip. Small models
fail this far more often than large ones. `format:json` removes the class of
failure where the action was right but the wrapping was prose.

**Honesty.** `format:"json"` guarantees *valid JSON*, not the *right schema* —
the model can still emit `{"foo": 1}`. So `_parse_llm_action` stays as the
second line of defence; this lever reduces nudges, it does not replace parsing.
Must degrade gracefully: a gateway that rejects `response_format` has to fall
back to an unconstrained call, or the lever trades a parse failure for a
request failure. Label: **mechanical**, unmeasured on `qwen2.5-coder:7b`.

## 2. Structured error feedback — `reflexion`

**What it does.** When a tool run or an action fails, feed the model a terse,
categorised reason and a concrete next-step constraint, instead of a raw error
blob — a lightweight Reflexion ("here is why that failed, do X instead").

**Where it hooks in.** The agent loop already appends corrective user turns:

- bad-JSON nudge, `orchestrator/main.py:5171`
- repeated-failure STOP (`"has failed N times … choose a DIFFERENT tool"`),
  `orchestrator/main.py:5204`
- duplicate-command STOP (`"you already ran {tool} N times … tools you have
  NOT tried: …"`), `orchestrator/main.py:5227`

So a seed of this is **already shipped**. The lever generalises it: classify
the tool result (non-zero exit, empty output, scope refusal stamped by the
proxy — detectable via `http_capture.answered`,
`orchestrator/http_capture.py:72`, which already distinguishes *our* refusal
from the target's) and emit one structured line the small model can act on.

**Failure mode addressed.** A small model loops on a command that cannot
succeed (wrong flag, out-of-scope host, tool not enabled), burning its turn
budget. The existing `failed_commands` / `recent_commands` guards stop the
loop bluntly; structured feedback aims to redirect it productively.

**Honesty.** The three existing nudges already cover the worst loops, so the
marginal value is the *quality* of redirection, not its existence. Risk: more
feedback text costs context budget on a model that is already context-starved —
keep each reflection to one line. Label: **mechanical** for the categorisation,
**speculative** for whether richer text beats the blunt STOP on a 7B.

## 3. Dynamic phase-scoped tool menu — `phase_tool_menu`

**What it does.** Show the model only the tools relevant to the current phase
(e.g. recon tools during discovery, injection tools during exploitation)
instead of the full enabled set every turn.

**Where it hooks in.** `render_system_prompt` (`orchestrator/main.py:2361`)
builds the menu from `TOOL_USE_SYSTEM_PROMPT` (line 1339); the per-turn
reminders use `tools_str` (`orchestrator/main.py:4967`). A phase→tool-subset
map would filter both.

**Failure mode addressed.** A 30-tool menu (`standard_20`/`full_30` presets) is
a large branching factor for a small model; it picks a plausible-but-wrong tool
and wastes turns. Narrowing the menu narrows the decision.

**Honesty — this one is genuinely speculative.** The agent's phase signal today
is coarse: `phase = "scan" if turn < 3 else "test"`
(`orchestrator/main.py:5041`). There is no fine-grained phase state machine in
the agent lane (the `chain_phase` machinery, `main.py:4925`, is for multi-
session chains, not within-session phases). So this lever needs a real phase
model built first, and **hiding a tool the model wanted is a regression risk**:
it directly tensions CLAUDE.md #2 ("declare, don't silently drop"). A hidden
tool must be shown as disabled-with-reason, not vanished. Until the phase model
exists and that tension is resolved, treat this as a research item, not a
scheduled slice.

## 4. Few-shot action exemplars — `action_exemplars`

**What it does.** Prepend 2–3 worked `{"action": …}` examples to the system
prompt so the model has a concrete pattern to imitate.

**Where it hooks in.** `render_system_prompt` (`orchestrator/main.py:2361`),
appended to `TOOL_USE_SYSTEM_PROMPT`. The prompt already carries one inline
example (the JSON nudge at `main.py:5173` shows the shape); this makes it a
first-class, always-present block under the flag.

**Failure mode addressed.** Small models produce malformed or empty actions
most often in the first few turns, before any tool feedback has shown them the
expected shape. Exemplars front-load that shape.

**Honesty.** Exemplars cost context budget (CLAUDE.md note: injected volume
costs recall dose-dependently, `orchestrator/main.py:4609`), and can bias the
model toward the exemplified tools — a measured risk on this codebase, where
wholesale playbook injection hurt recall. Keep exemplars generic (shape, not
target-specific commands). Overlaps with lever 1: if `structured_json` already
fixes the wrapping, exemplars mainly help *schema* adherence. Label:
**speculative**; measure against `structured_json` alone before shipping both.

## 5. Turn-budget framing — `soft_turn_budget`

**What it does.** Change how the turn budget is presented to the model, to
counter two opposite small-model pathologies: rushing to `done` early, or
stalling and repeating.

**Where it hooks in.** The per-turn status the loop surfaces (`turn+1/max_turns`
appears in logs and progress, `orchestrator/main.py:5083,5122`) and the
stagnation guard (`orchestrator/main.py:5057-5069`). The lever would soften the
explicit countdown in anything the model sees, while keeping the real cap and
stagnation stop unchanged server-side.

**Failure mode addressed.** A model told "turn 18/20" may call `done`
prematurely; a model with no sense of budget may churn. The aim is steady
exploration without the countdown pressure.

**Honesty.** This is the softest lever here — **speculative**, and partly a
prompt-wording change whose effect is hard to separate from noise. The real
guardrails (`max_turns`, stagnation detection) must not move; only the framing
does. Do not ship without a measured recall/precision comparison, since it
touches the loop that every campaign ran under.

## 6. `num_ctx` sizing — **shipped**

**What it does.** Sizes the local model's context allocation per run so the
whole prompt is actually seen.

**Where it hooks in — already wired.** `chat(num_ctx=…)`
(`orchestrator/llm_client.py:350`) → `_ollama_chat` sets
`options["num_ctx"]` (line 69). The agent loop derives the value from the same
budget as its trim logic: `_ctx_budget` / `_ctx_alloc`
(`orchestrator/main.py:4642-4651`), from `context_budget_tokens`
(`main.py:975`) and `model_context_window` (`main.py:946`), plus
`CONTEXT_RESPONSE_HEADROOM` (`main.py:941`).

**Failure mode addressed.** Ollama allocates a 4096-token default regardless of
what the model supports and **drops overflow with no error**
(`orchestrator/llm_client.py:60-69`). Without `num_ctx` the model silently
never sees the tail of its own prompt. The trim budget and `num_ctx` are
derived from one number on purpose: raising one without the other trades a
visible trim for an invisible truncation.

**Honesty.** Listed for completeness because it is the foundational small-model
lever and the others assume it. It is a hosted-provider no-op (remote providers
size their own context; `num_ctx` is ignored, `chat` docstring, line 352).
Nothing to build here — do not re-report it as missing.

## What this spec deliberately excludes

- **Fine-tuning / quantisation changes.** Out of scope by the task's own
  constraint; and the machine already carries target-tuned variants
  (`…-juicy2`, `…-cipher`) whose silent substitution `ensure_model_available`
  (`orchestrator/llm_client.py:317`) exists to prevent. Keep that separation.
- **New operator setup.** Every lever is a flag on the existing request path;
  none requires a new service, model pull, or env file beyond the flag itself.
- **Changing the three frozen arms.** None of these flags may be folded into
  `TOOLSET_PRESETS` or the recorded presets; they are product levers added
  alongside, and each defaults OFF.

## Measurement note (CLAUDE.md #7)

Each lever's claim to improve a small model is empirical and currently
**unmeasured** except where marked shipped. Before any lever is promoted from
roadmap, it needs a recall/precision comparison against the `ai_only` baseline
(`orchestrator/runconfig.py:69`) on the same targets, with the flag the only
variable — the same arm-isolation discipline the thesis presets enforce. This
document does not assert any lever *does* improve performance; it asserts where
each would hook in and what failure each targets.
