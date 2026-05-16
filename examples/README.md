# deps-doctor — examples

Each scenario shows: a synthetic audit input, the exact command, and the unified report `deps-doctor` produces.

---

## Scenario 1 — npm + pip + cargo + go (the polyglot case)

**Setup:** You're working on a service that has `package.json`, `pyproject.toml`, `Cargo.toml`, AND `go.mod`. All four audit tools are installed.

**Command:**

```sh
python3 scripts/doctor.py --format md
```

**Sample output:**

```
## deps-doctor report

### npm — 1 high, 1 moderate
- **GHSA-wf5p-g6vw-rhxx** in `axios@<1.6.0` → fixed in `1.6.0` (high)
- **GHSA-jf85-cpcp-j695** in `lodash@<4.17.21` → fixed in `4.17.21` (moderate)

### pip — clean

### cargo — clean

### go — _skipped: govulncheck not installed_
```

Three signals in one report: real advisories (npm), clean ecosystems (pip, cargo), and missing tooling (go) — explicitly marked, never silently passed.

---

## Scenario 2 — filter by severity

You only want to look at the high+ stuff before the standup:

```sh
python3 scripts/doctor.py --severity high
```

Suppresses anything below `high` in the report. The four levels are `low | moderate | high | critical`.

---

## Scenario 3 — single ecosystem

Working in a monorepo and only care about Python today?

```sh
python3 scripts/doctor.py --ecosystem pip --format md
```

Skips the npm / cargo / go detection entirely.

---

## Scenario 4 — missing tools are surfaced, not hidden

The most important guarantee of `deps-doctor`: it does NOT silently return clean when the audit binary is missing.

```sh
# In a repo with package.json but no npm installed:
python3 scripts/doctor.py --ecosystem npm --format md
```

```
## deps-doctor report

### npm — _skipped: tool not installed_
```

This is the safe failure mode. CI scripts can grep `skipped:` to fail or warn on missing tooling.

---

## Sample input fixture

[`sample-npm-audit.json`](./sample-npm-audit.json) — a minimal `npm audit --json` payload showing the input shape `deps-doctor` parses. Useful for testing your own integrations.
