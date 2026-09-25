# WIENER Release Notes

## Public-submission contents

The submission contains the FastAPI PoC, provider adapters, recorded replay
fixtures, config YAML, Judge Mode, tests, documentation, and curated dashboard
evidence. It intentionally excludes `.env`, API keys, diagnostics, runtime
logs, replay output, caches, local experiment captures, and local environments.

## Verification procedure

Run these from the repository root before a submission or demo:

```bash
python -m pytest -q
./run_healthcheck
./run_replay --scenario ALL --validate --runs 3
docker build -t wiener:local .
```

## Evidence provenance

The authoritative metrics are preserved from the recorded 135-trial run. The
manifest's `source_provenance` field compares the recorded code fingerprint
with the current source tree. It currently reports `STALE` because the run was
recorded before the current `main` source changes. This is intentional and
visible in the dashboard; the stored metrics are not presented as a
current-code run. A current-code lock requires rerunning the experiment.

## Change policy

Configuration, safety constraints, provider behavior, or replay fixtures must
be changed deliberately and verified with the suite and replay validation.
Never add credentials, request/response diagnostics, or runtime JSONL logs to
the public repository.
