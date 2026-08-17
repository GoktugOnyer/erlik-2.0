# Attribution — Claude-BugHunter skills

Every `.md` file in this directory is vendored from **elementalsouls/Claude-BugHunter**.

- Source: https://github.com/elementalsouls/Claude-BugHunter
- Author: Sachin Sharma
- Content licence: **Creative Commons Attribution 4.0 International (CC BY 4.0)**
  — https://creativecommons.org/licenses/by/4.0/
- Repository code licence (not used here): MIT, Copyright (c) 2026 Sachin Sharma

CC BY 4.0 permits commercial use and redistribution, including inside an
MIT-licensed project, **provided attribution is given and changes are indicated**.
That is what this file and the entry in [`THIRD_PARTY_LICENSES.md`](../../../THIRD_PARTY_LICENSES.md)
provide.

## Why this sits in its own directory

The rest of `skills_catalog/skills/` is vendored from
transilienceai/communitytools under **MIT**. Merging two differently-licensed
corpora into the same folders would make the provenance of any individual file
ambiguous, and CC BY 4.0 carries an attribution obligation MIT does not. Keeping
them separate means the licence of a file is always answerable from its path.

Contrast with `techniques_catalog/`: HackTricks is CC BY-**NC** 4.0, whose
NonCommercial clause is incompatible with erlik's MIT grant, so that corpus is
referenced by index and never vendored. This one is CC BY 4.0 — no NC clause —
so it can be.

## Changes made

The files are the upstream text, unmodified. Only the layout changed:

- `skills/<name>/SKILL.md` → `<name>.md`
- `skills/<name>/<subdir>/<file>.md` → `<name>-<file>.md`

Flattened so `orchestrator/skills.py` indexes them, and the `hunt-<class>` stem is
preserved because class routing anchors on it (`_class_candidates` matches
`-cors` inside `hunt-cors`).

## How these are used

They are a **corpus the router selects from**, not text injected wholesale. Any
one session receives at most a few files under a character budget
(`select_skill_files`, default 14 KB). Growing the pool the router chooses from
is a different thing from growing what any run receives, and the budget cap is
what keeps them different.

**Measured caveat.** That distinction is about corpus SIZE. What a run actually
receives is a separate question, and the answer is currently unfavourable: on
both a 7B and a 27B, injecting this material COSTS recall — −0.100 and −0.071
respectively — with precision falling alongside it, so it is not trading breadth
for accuracy. See [`docs/CONTEXT_ALLOCATION_EXPERIMENT.md`](../../../docs/CONTEXT_ALLOCATION_EXPERIMENT.md).
An earlier reading blamed context crowding (r = −0.796 under a 4,096-token
window); giving the models their real windows made the effect worse, not better,
which rules that explanation out.
