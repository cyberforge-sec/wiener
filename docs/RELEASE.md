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

The historical `release/MANIFEST.sha256` is not part of the public submission:
it was a local snapshot checksum and is deliberately excluded so it cannot
make stale byte-for-byte claims after repository preparation.

## Change policy

Configuration, safety constraints, provider behavior, or replay fixtures must
be changed deliberately and verified with the suite and replay validation.
Never add credentials, request/response diagnostics, or runtime JSONL logs to
the public repository.
