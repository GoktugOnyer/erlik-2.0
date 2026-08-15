# skills_catalog — attribution

The markdown knowledge files under `skills_catalog/skills/<class>/` are vendored,
unmodified, from the **`skills/*/reference/`** directories of
[transilienceai/communitytools](https://github.com/transilienceai/communitytools)
(MIT License, Copyright (c) 2025 Transilience AI).

They are used here purely as a **knowledge corpus** — erlik loads and injects
relevant excerpts into its agent loop's system prompt (see
`orchestrator/skills.py`). The Claude-Code-specific `SKILL.md` manifests,
`scenarios/`, and executable `tools/` from the upstream skills are intentionally
NOT included.

Some of these references in turn incorporate payload material from
PayloadsAllTheThings and PortSwigger Web Security Academy write-ups.

See the repository root `THIRD_PARTY_LICENSES.md` and
`licenses/communitytools-MIT.txt` for the full license text.

## Dual use

This corpus serves two consumers:

1. **erlik's agent loop** — `orchestrator/skills.py` selects and injects relevant
   files (`ERLIK_SKILLS=1`), and `python -m orchestrator.skills "<hint>"` prints
   the same context for any other model/API.
2. **Claude Code skills** — each `skills/<class>/` carries a `SKILL.md`, so this
   directory is also an installable Claude Code plugin
   (`erlik-security-skills`). From the repo root:

   ```bash
   /plugin marketplace add .
   /plugin install erlik-security-skills@erlik
   # then invoke e.g.  /erlik-security-skills:injection
   ```

