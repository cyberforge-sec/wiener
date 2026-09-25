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

The authoritative run is `authoritative_20260925_zero_degraded`: 135 live
trials, validation 16/16 PASS, zero degraded provider results, and nine recorded
provider retries. Its manifest reports `source_provenance: MATCH`, so the code
fingerprint matches the current `main` source tree. The earlier
`authoritative_20260912_clean_2252` run remains available as historical
evidence and is not presented as the current-code result.

## Change policy

Configuration, safety constraints, provider behavior, or replay fixtures must
be changed deliberately and verified with the suite and replay validation.
Never add credentials, request/response diagnostics, or runtime JSONL logs to
the public repository.
