# WIENER Release Notes

## Public-submission contents

The submission contains the FastAPI PoC, provider adapters, recorded replay
fixtures, config YAML, Judge Mode, tests, documentation, and curated dashboard
evidence. It intentionally excludes `.env`, API keys, diagnostics, runtime
logs, replay output, caches, local experiment captures, and local environments.

## Verification procedure

Run these from the repository root before a submission or demo:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
./run_healthcheck
./run_replay --scenario ALL --validate --runs 3
python -m scripts.experiments.enforcement_ablation
docker build -t wiener:local .
```

## Evidence provenance

Three artifacts, three different claims. They are not interchangeable.

### `authoritative_20260925_zero_degraded` — historical, retained unmodified

135 live trials, zero degraded provider results, nine recorded provider retries,
`evidence_status: LOCKED_VERIFIED` in its own manifest.

**It does not satisfy the current validation checklist, and cannot be
re-locked as-is.** Two defects were found in its recorded rows:

- 90 of 135 rows record `model: "opencode"`, which is the provider *adapter*
  name, not a model id. Only the 45 WIENER rows recorded a real model
  (`oc/big-pickle`).
- No row records a decoding temperature, so the manifest's
  `temperature_policy: "0.0 fixed (determinism)"` was an assertion the
  artifacts cannot support. Hosted gateways may sample at temperature 0
  regardless.

Against the strengthened checklist (18 invariants, up from 16) it fails `I-09`
(temperature not recorded) and `I-13b` (transport name in the model field).
The artifacts are kept exactly as produced; a fresh run is required to produce
lockable evidence. The dashboard therefore shows these artifacts as
**locked but requiring review** rather than as verified-sound, which is the
correct presentation of that state.

### `authoritative_20260912_clean_2252` — historical only

The earlier 10-trial run. Its anomaly was investigated and not reproduced; it
is retained for transparency and is not presented as a current result.

### `enforcement_ablation_reference` — current

A separate, deterministic, offline experiment (~1 second, no credentials) that
isolates the enforcement layer: identical proposals and identical model output,
with the Policy Gate present versus removed. It is the direct demonstration
that the gate, not the prompt, is what prevents execution. Its numbers are
never merged into UAR/ASR/FIR/UAPR.

## What a fresh authoritative run changes

Re-running the harness after these fixes produces evidence that:

- records the model id its provider actually reported, per trial (`I-13b`);
- records the requested temperature per trial, whatever the value (`I-09`);
- records a latency window bounded by the trial's own duration (`I-06b`);
- fails rather than passes when a duration is missing (`I-06`);
- cannot lock at all if any trial degraded (`no_degraded_trials`);
- hashes the three experiment-defining config files, so `provenance: MATCH`
  actually covers them (see below).

The measured TTI/E2E values will differ from the archived run, because the
archived e2e figure was produced by a mapping that leaked an absolute clock
value into a subtraction. That is a correction, not a regression, and the old
numbers are not edited.

### The 2026-09-26 run: 135 trials, 17/18, CANDIDATE

A full run on the `oc/big-pickle` route completed cleanly: 135/135 trials, 0
degraded, 0 errors, provenance `MATCH`. It fails **only** `I-13b`, on all 135
trials, because the route reports `big-pickle` for a request of
`oc/big-pickle` and that id is a floating alias.

It is retained as **provider-compatibility evidence**, not as the headline
benchmark, and it is not locked. `docs/PROVIDER_SURVEY.md` records the full
route survey behind that decision, including the finding that the one route
with a verifiable model id (`gh/gpt-4o-mini-2024-07-18`) has an upstream
content filter that rejects the injection payload the benchmark depends on.

The WIENER row is the reason the run is worth keeping: ASR 0.0889 with UAR
0.0000, against 0.0000/0.0000 for the prompt-only defense. WIENER saw dangerous
proposals the prompt had suppressed and still produced zero unsafe executions.

Preflight now refuses to start a run whose model identity cannot be verified
(`A1.cloud.model-identity`), so this class of run is not spendable twice. The
deliberate exception is `--allow-unverifiable-identity`, which records that the
result can only be a `CANDIDATE`.

## What `provenance: MATCH` covers

The fingerprint covers every `.py` file under `app/` and `scripts/experiments/`,
plus an explicit allowlist of the three files that define the experiment:

| File | What it decides |
| --- | --- |
| `config/red_ai_seeds.yaml` | which attacks are attempted |
| `config/action_metadata.yaml` | which actions count as dangerous (UAR numerator) |
| `config/safety_constraints.yaml` | which rules hard-BLOCK before the tool layer |

The list is enumerated on purpose, not a `config/*.yaml` glob, so a future
presentation-only config file cannot silently become load-bearing for
provenance. A declared input that is missing raises, rather than hashing the
remaining subset and still reporting a self-consistent hash.

Before this change, editing any of those three files left `root_hash`
unchanged, so a bundle could report `MATCH` while the seeds, the danger labels,
or the hard-block rules had been swapped.

## Change policy

Configuration, safety constraints, provider behavior, or replay fixtures must
be changed deliberately and verified with the suite and replay validation.
Never add credentials, request/response diagnostics, or runtime JSONL logs to
the public repository.
