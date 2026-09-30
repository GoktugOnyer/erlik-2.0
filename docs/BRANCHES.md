# Erlik 2.0 — branch model

The repository serves two audiences, so it keeps two long-lived lines. This is
the map.

| Line | Branch | State | Rule |
|---|---|---|---|
| **Thesis** | `master` | Frozen | The MSc thesis artifact: recorded campaigns, the frozen `TOOLSET_PRESETS` (core_10 / standard_20 / full_30), and the reproducibility docs. Its figures reproduce from this commit. **Nothing new is pushed here.** |
| **Development** | `develop` | Active | Where product work continues. Branch new work off `develop` and merge back into it. |

`master` stays the default branch and the citable thesis reference. `develop`
carries everything since — the 136-commit development history plus ongoing work.

## The `thesis-v1.0` tag

The thesis commit should carry an annotated tag, `thesis-v1.0`, pointing at
`master`. The cloud session token cannot push tags (GitHub returns 403 on
ref creation for tags, the same limitation that blocks ref deletion), so this
is a one-line manual step from a local clone:

```bash
git tag -a thesis-v1.0 <master-sha> -m "Thesis v1.0 — frozen, reproducible thesis artifact"
git push origin thesis-v1.0
```

## Branch cleanup

The old per-feature `claude/*` branches are all merged into `develop` and can be
deleted. Because the session token cannot delete refs, a ready-to-run script
lists exactly the merged branches (excluding `master`, `develop`, and the two
branches deliberately kept). Run it from a local clone:

```bash
git fetch --prune origin
git branch -r --merged origin/develop | grep 'origin/claude/' | sed 's#origin/##' \
  | grep -vE 'fervent-sagan|project-status-review' \
  | xargs -I{} git push origin --delete {}
```

Kept deliberately: `master`, `develop`, and `claude/project-status-review-8bw8z0`
(the old development PR's head — its work is in `develop`; delete once you're
sure you don't need the PR reference).

## Working here

- **Reproducing thesis results** → check out `master`. It is deliberately
  historical; see `docs/METHODOLOGY.md` and `docs/REPRODUCIBILITY.md`.
- **Building the product** → work on `develop`. Thesis invariants (the frozen
  presets, the campaign-era prompt in the docs) are still enforced by tests, so
  product changes live *alongside* them rather than editing the recorded record —
  see `CLAUDE.md`, "Thesis vs product".
