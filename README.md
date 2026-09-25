# WIENER

WIENER is a sandboxed AI-vs-AI security proof of concept for evaluating how a policy-controlled SOC workflow responds to adversarial and ambiguous alerts. It is a HackNusa 2026 submission, not a production security-control plane.

## 1. What is WIENER?

An LLM-assisted SOC Agent may propose an action from untrusted alert text. WIENER separates that **proposal** from **execution authority**: the SOC Agent proposes, while a deterministic Risk Engine and Policy Gate decide whether the simulated tool layer may act. Red AI provides adversarial input and Blue AI evaluates the resulting trajectory.

> **WIENER uses a provider-agnostic cloud inference layer, allowing different
> cloud LLM providers to be integrated through adapters while preserving the
> same deterministic security and execution boundary.**

In one line:

```text
MODEL CAN CHANGE      PROVIDER CAN CHANGE      INFERENCE CAN CHANGE
                        ↓
              EXECUTION AUTHORITY DOES NOT CHANGE
```

Swapping `provider: openai / model: gpt-4o-mini` for
`provider: anthropic / model: claude-…` changes which model writes the SOC
proposal and nothing else. Risk scoring, policy thresholds, action criticality,
hard constraints, execution authorization and the executor re-check are
identical, and the test suite asserts that invariance rather than asserting it
in prose (`tests/test_provider_agnostic.py`).

### Three separate things, so they are not confused

| | What it is | Fixed? |
| --- | --- | --- |
| **Product architecture** | Provider-agnostic. Inference is an adapter behind a contract. | Never vendor-locked. |
| **Default runtime** | Cloud first, local fallback, replay last resort. | The same ladder for every cloud. |
| **Headline benchmark** | The 135-trial run was produced on one specific provider configuration. | An experiment setting, not a product limit. |

A benchmark pinned to one model is a *measurement*. Requiring that model to
run the product would be a *dependency*. Only the first is true here.

## 2. Architecture

```text
Attacker / Input → SOC Agent → Trajectory Engine → Blue AI → Risk Engine → Policy Gate → Simulated Tool Execution
```

- **SOC Agent:** proposes a typed action from a `SOCContext`.
- **Trajectory Engine:** preserves proposal, history, and provenance.
- **Blue AI:** assesses trust, deviation, criticality, and privilege impact.
- **Risk Engine:** calculates deterministic risk and matches YAML constraints.
- **Policy Gate:** returns `ALLOW`, `REVIEW`, or `BLOCK`.
- **Tool layer:** acts only after `ALLOW`, and labels every result simulated.

The provider ladder fails downward: cloud → local Ollama → deterministic
`replay`. The cloud tier is a **pluggable adapter**, not a vendor: the same
Risk Engine, Policy Gate, hard constraints and executor re-check run whichever
model is behind it. The UI reports the tier actually used.

Two evaluators, two different clouds, one identical ladder:

```text
cloud = OpenAI        cloud = OpenCode / Big Pickle
      ↓                     ↓
   OpenAI                OpenCode
      ↓ fails              ↓ fails
   Ollama                Ollama
      ↓ fails              ↓ fails
   Replay                Replay
```

The cloud slot is a single rung regardless of which adapter fills it, so the
fallback order and the security pipeline are byte-identical in both cases.

## 3. Safety Boundary

WIENER is a simulation. It does not isolate real endpoints, disable real accounts, change firewall rules, connect to a production SIEM, or perform real security actions. `SimulatedToolExecutor` is the only execution layer; even `executed=true` is a simulated event. Replay is recorded deterministic data, not live inference.

## 4. Repository Structure

```text
app/          FastAPI app, pipeline, providers, Judge Mode, replay
config/       Action metadata, safety constraints, Red AI seeds
tests/        Pytest suite
benchmarks/   Optional local benchmark harness
scripts/      Health check and experiment utilities
docs/         Architecture, setup, runbook, contracts, benchmark notes
data/         Recorded replay fixtures and curated dashboard evidence
release/      Release notes
```

## 5. Requirements

- Python 3.12 is the verified release environment; Python 3.10+ is the
  application minimum enforced by the health check. Use Docker when a matching
  Python environment is unavailable.
- Docker Engine for Docker use only.
- Ollama for local inference only; it is the currently implemented local
  provider API. The example model is `qwen2.5:1.5b`.
- Network for cloud inference only. Replay works offline.

No portable RAM or disk minimum is claimed because this repository has no validated cross-host measurement.

> **Live evaluation is required for the competition.** Replay is only a setup
> smoke test and offline safety net; it must not be presented as live evidence.

### Choose a run mode

The repository does not include your API key or local model. For the required
live evaluation, choose Cloud or Local. Replay is for setup verification only:

| Purpose | What you provide | `WIENER_LLM_FORCE` |
| --- | --- | --- |
| Setup smoke test / offline verification | Nothing beyond the application | `replay` |
| **Live evaluation: cloud** | Your own provider key, base URL, and model | `openai_compatible` |
| **Live evaluation: local** | Ollama and a model installed on the same machine | `local` |
| Automatic live selection | Configured cloud and/or local provider | empty |

`opencode` remains accepted as a legacy alias for the cloud tier, because older
`.env` files and stored evidence use it; it is not a product requirement. The
checked-in `.env.example` is safe for setup: its cloud key is empty and its
default is `replay`.

## 6. Quick Start

The first run is intentionally offline and deterministic. It verifies the
installation only; it is not the required live competition evaluation. It uses
no API key, no Ollama, and no network call:

```bash
git clone https://github.com/cyberforge-sec/wiener.git
cd wiener
python3 -m venv .venv
. .venv/bin/activate                 # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cp .env.example .env
WIENER_LLM_FORCE=replay ./run_healthcheck
WIENER_LLM_FORCE=replay ./run_replay --scenario ALL
WIENER_LLM_FORCE=replay python -m app.main
```

Open `http://localhost:8000/judge`, leave the provider set to **Replay**, and
run a scenario. Stop the server with `Ctrl+C`. The copied `.env` is safe for
this smoke test: its cloud key is empty and its provider default is `replay`.

Before the live competition evaluation, edit `.env` using the Cloud or Local
section below and verify `/health` reports that live provider. To
restore automatic selection, set `WIENER_LLM_FORCE=` after configuring the
provider you want to try first; the ladder is cloud → local Ollama → replay.

## 7. Run Without Docker

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
WIENER_LLM_FORCE=replay ./run_healthcheck
WIENER_LLM_FORCE=replay python -m app.main
```

In another terminal, verify `curl http://localhost:8000/health` and run:

```bash
curl -X POST http://localhost:8000/judge/run -H 'content-type: application/json' -d '{"provider":"replay","scenario":"normal"}'
```

The health response should be `ok`; the Judge response identifies `replay`. To
restore automatic cloud → local Ollama → replay selection, set
`WIENER_LLM_FORCE=` in `.env` and restart the server. Do not merely remove a
shell override while `.env` still contains `WIENER_LLM_FORCE=replay`.

## 8. Run With Docker

Build once, then choose exactly one runtime mode:

```bash
docker build -t wiener:local .
docker run --rm -p 8000:8000 -e WIENER_LLM_FORCE=replay wiener:local
```

The command above is the safest setup smoke test. It is not the required live
competition evaluation. Visit `http://localhost:8000/judge` or call `/health` in
another terminal. If port 8000 is busy, use `-p 8001:8000`.

For a named background container with an inspectable health status:

```bash
docker run -d --name wiener-demo -p 8000:8000 -e WIENER_LLM_FORCE=replay wiener:local
docker inspect --format '{{.State.Health.Status}}' wiener-demo
docker logs -f wiener-demo
docker stop wiener-demo
docker rm wiener-demo
```

For cloud mode, put the evaluator's real credentials in `.env` and explicitly
select the cloud adapter:

```bash
docker run --rm -p 8000:8000 --env-file .env -e WIENER_LLM_FORCE=openai_compatible wiener:local
```

For local Ollama in Docker, use the host gateway command in section 10. If a
cloud run fails inside Docker, the local fallback also needs that host gateway;
otherwise WIENER falls through to replay. Never bake `.env`, keys, or models
into the image; `.dockerignore` excludes secrets, logs, and cache.

## 9. Cloud LLM Setup

The cloud tier is an **adapter behind a common contract**, so the inference
provider is replaceable without touching a single security control. Two
adapters are implemented and covered by the test suite:

| `WIENER_CLOUD_ADAPTER` | Wire format | Notes |
| --- | --- | --- |
| `openai_compatible` (default) | `POST {base_url}/chat/completions` | Covers OpenAI and any OpenAI-compatible gateway (Groq, OpenRouter, …) by changing only base URL, key and model. |
| `anthropic` | `POST {base_url}/v1/messages` | Native Messages API: `system` is a top-level parameter, auth is `x-api-key`, the response is typed content blocks, and there is no `response_format`. All of that is translated inside the adapter. |

Switching provider changes **only** which model produced the SOC proposal. Risk
scoring, thresholds, action criticality, hard constraints, execution
authorization and the executor re-check are identical, and the test suite
asserts that invariance directly (`tests/test_provider_agnostic.py`).

The documented variables are `WIENER_CLOUD_*` plus `WIENER_ANTHROPIC_*`; legacy
`WIENER_OPENCODE_*` variables remain accepted for backwards compatibility. Copy
`.env.example` to `.env`, then set the key and, if needed, the URL/model to
values belonging to the evaluator:

```env
# Leave blank until you have a real key. Do not use a placeholder value.
WIENER_CLOUD_API_KEY=
WIENER_CLOUD_BASE_URL=https://api.openai.com/v1
WIENER_CLOUD_MODEL=gpt-4o-mini
WIENER_LLM_FORCE=openai_compatible
WIENER_LLM_TIMEOUT_S=30
```

Replace the URL and model with values from your own OpenAI-compatible provider.
`WIENER_CLOUD_TEMPERATURE` and `WIENER_CLOUD_RESPONSE_FORMAT` are optional. An
empty key skips cloud; an unavailable cloud tier falls to local then replay.
Do not commit `.env`.

### Updating an existing setup

If you already have a local `.env` from an earlier WIENER checkout, rename
these variables. Your API key value, URL, and model value do not change.

| Old variable | New variable |
| --- | --- |
| `WIENER_OPENCODE_API_KEY` | `WIENER_CLOUD_API_KEY` |
| `WIENER_OPENCODE_BASE_URL` | `WIENER_CLOUD_BASE_URL` |
| `WIENER_OPENCODE_MODEL` | `WIENER_CLOUD_MODEL` |
| `WIENER_OPENCODE_TEMPERATURE` | `WIENER_CLOUD_TEMPERATURE` |
| `WIENER_OPENCODE_RESPONSE_FORMAT` | `WIENER_CLOUD_RESPONSE_FORMAT` |
| `WIENER_OPENCODE_DIAG_PATH` | `WIENER_CLOUD_DIAG_PATH` |

Then restart the application. For a native run, stop it with `Ctrl+C` and run
`python -m app.main` again. For Docker, rebuild the image and run it with the
same local `.env`:

```bash
docker build -t wiener:local .
docker run --rm -p 8000:8000 --env-file .env -e WIENER_LLM_FORCE=openai_compatible wiener:local
```

The old names remain accepted for backward compatibility, so this migration is
recommended for clarity, not an emergency breaking change.

Only providers that are actually implemented and tested are listed. An
untested adapter is not claimed.

| Cloud choice | Works now? | Adapter | Notes |
| --- | --- | --- | --- |
| OpenAI API | Yes | `openai_compatible` | Configure its standard `/v1` base URL, key, and model. |
| Any OpenAI-compatible provider/gateway | Yes | `openai_compatible` | Configure that service's base URL, key, and model. Nothing else changes. |
| Anthropic native Messages API | Yes | `anthropic` | Set `WIENER_CLOUD_ADAPTER=anthropic` and the `WIENER_ANTHROPIC_*` values. |
| Gemini native API | Not yet | — | No dedicated adapter is implemented or tested. Use an OpenAI-compatible gateway, or add one behind the same contract. |

## 10. Local LLM Setup (Ollama)

The local provider currently calls the Ollama HTTP API (`/api/generate`), so
**Ollama is required if you select local mode**. It is not required for cloud
or replay mode. For a native local run, install/start Ollama and pull the
selected model:

Use two terminals so the blocking server command does not hide the setup steps:

```bash
# Terminal 1: start Ollama and leave it running
ollama serve

# Terminal 2: pull once, then verify
ollama pull qwen2.5:1.5b
curl http://localhost:11434/api/tags
```

Configure `WIENER_LOCAL_HOST`, `WIENER_LOCAL_MODEL`, `WIENER_LOCAL_TIMEOUT_S`,
`WIENER_LOCAL_MAX_TOKENS`, and `WIENER_LOCAL_KEEP_ALIVE`. For a native local
run, put these values in `.env`:

```env
WIENER_LLM_FORCE=local
WIENER_LOCAL_HOST=http://localhost:11434
WIENER_LOCAL_MODEL=qwen2.5:1.5b
WIENER_LOCAL_TIMEOUT_S=60
WIENER_LOCAL_MAX_TOKENS=128
WIENER_LOCAL_KEEP_ALIVE=5m
```

`WIENER_LOCAL_HOST` is the Ollama HTTP endpoint; `WIENER_LOCAL_MODEL` is the
model tag returned by `ollama pull`. For Docker Desktop, use
`http://host.docker.internal:11434`; on Linux also add the host gateway:

```bash
docker run --rm -p 8000:8000 --add-host=host.docker.internal:host-gateway -e WIENER_LLM_FORCE=local -e WIENER_LOCAL_HOST=http://host.docker.internal:11434 -e WIENER_LOCAL_MODEL=qwen2.5:1.5b wiener:local
```

`localhost` inside a container means the container itself, not host Ollama.
Ollama is not required for Cloud mode, but it is required if you choose Local
mode. Replay remains available as a setup fallback, not as the live result.
Other local runtimes (LM Studio, vLLM, llama.cpp, LocalAI) are not direct
local-provider backends in this release unless they expose an Ollama-compatible
API.

| Local choice | Works now? | Notes |
| --- | --- | --- |
| Ollama | Yes | Required for the built-in `local` provider; choose any Ollama model that can return the required JSON. |
| No local runtime | Yes | Use live Cloud; replay is only a setup fallback. |
| LM Studio, vLLM, llama.cpp, LocalAI | Not directly | Add an adapter, or expose an Ollama-compatible endpoint. |

## 11. Replay Mode

Replay uses the recorded response store and makes no cloud or Ollama request:

```bash
./run_replay --scenario ALL
./run_replay --scenario ALL --validate --runs 3
```

It is deterministic/offline verification, not live LLM inference and not a
substitute for the required live evaluation. Generated replay run files are
intentionally ignored by Git. This is the setup smoke test for an evaluator who
does not have an API key or Ollama.

## 12. Judge Mode

Start the server and open `/judge`. For the required live evaluation choose
**Cloud** or **Local (Ollama)**; these are alternatives, not two models that
must run together. The Cloud entry runs whichever adapter
`WIENER_CLOUD_ADAPTER` selects. Use **Replay** only for
offline setup checks. Choose `normal`, `prompt_injection`, or `adaptive`, then
select **Run**. **Replay** repeats the latest request and **Reset** clears
state. Evaluators should inspect the actual provider tier, pipeline stages,
policy verdict, and simulated-tool result.

## 13. API / Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Runtime status and resolved provider |
| `/analyze` | POST | Pipeline run for a `SOCContext` JSON body |
| `/dashboard` | GET | Read-only dashboard (`?format=json`) |
| `/judge` | GET | Interactive Judge Mode |
| `/judge/logo` | GET | Judge logo asset |
| `/judge/run` | POST | Run scenario; `?stream=true` starts SSE |
| `/judge/stream` | GET | SSE events for `run_id` |
| `/judge/replay` | POST | Repeat latest Judge request |
| `/judge/reset` | POST | Reset Judge session |
| `/judge/state` | GET | Latest Judge metadata |

## 14. Testing

The test dependencies are declared separately from the runtime dependencies, so a
clean clone can run the suite without installing anything extra by accident:

```bash
python -m pip install -r requirements-dev.txt   # includes requirements.txt + pytest
python -m pytest -q
WIENER_LLM_FORCE=replay ./run_healthcheck
WIENER_LLM_FORCE=replay ./run_replay --scenario ALL --validate --runs 3
```

Installing only `requirements.txt` gives you the application; the suite needs
`pytest` from `requirements-dev.txt`.

The health check reports unavailable cloud/Ollama as warnings because replay is a supported fallback.

### Test suite at a glance

The suite runs fully offline (replay/fake providers) and needs no credentials.
It covers the authorization boundary, provider contracts, retry and provenance
behaviour, the evidence/validation layer, and the presentation layer.

| Area | What is asserted |
| --- | --- |
| `test_policy_gate.py`, `test_tool_executor.py` | A non-`ALLOW` decision can never reach a simulated tool; the executor re-checks the decision itself; every action in the vocabulary has a simulated tool. |
| `test_metrics.py`, `test_dashboard.py` | UAR/ASR/FIR/UAPR are computed only from stored trial fields; malformed input raises instead of returning a plausible number. |
| `test_provider_contract.py` | Cloud and local providers report the model id and requested temperature; the local rung uses real system/user roles when the server supports it and says so when it does not. |
| `test_provenance.py` | A transport name in the `model` field, an unrecorded temperature, a missing duration, and an absolute clock value leaking into a latency delta are all failures. |
| `test_present.py` | The dashboard renders stored values rather than literals, and corrupt evidence fails closed. |
| `test_enforcement_ablation.py` | The ablation is deterministic, keeps its own artifacts, and cannot touch the authoritative evidence. |

## 15. Verification

- [ ] Application starts and `/health` returns `ok`.
- [ ] Replay scenarios are deterministic (setup smoke test only).
- [ ] The required live provider is selected and `/health` reports it.
- [ ] The dashboard discloses the recorded evidence source-provenance status.
- [ ] Cloud uses evaluator-provided configuration.
- [ ] Local mode reaches evaluator-provided Ollama.
- [ ] The safety boundary remains simulated.
- [ ] Tests pass in the evaluator environment.

## 16. Troubleshooting

| Problem | Cause | Fix |
| --- | --- | --- |
| `docker: command not found` | Docker is unavailable on `PATH`. | Install/start Docker Engine. |
| Port 8000 is in use | Another process owns the host port. | Stop it or use `-p 8001:8000`. |
| Ollama unavailable | Service stopped or bad host. | Run `ollama serve`, verify `/api/tags`, set `WIENER_LOCAL_HOST`. |
| Model not found | Configured tag was not pulled. | Run `ollama pull <model>`. |
| Cloud key missing | Key is blank. | Add evaluator key to local `.env`, or use local/replay. |
| First run unexpectedly calls cloud | A placeholder or copied key is present and replay is not selected. | Set `WIENER_CLOUD_API_KEY=` and `WIENER_LLM_FORCE=replay`. |
| Invalid cloud URL | Provider API root is incorrect. | Set its OpenAI-compatible base URL, normally ending `/v1`. |
| Container cannot reach Ollama | Container localhost differs from host localhost. | Use `host.docker.internal:11434`; Linux also needs `--add-host=host.docker.internal:host-gateway`. |
| Dependency install fails | Unsupported Python or unavailable package index. | Use Python 3.10+, recreate venv, restore package-index access. |

## 17. Security Notes

Never commit `.env`, API keys, tokens, provider diagnostics, runtime logs, or environments. Diagnostic capture is disabled by default because responses can be sensitive. The Policy Gate is a simulation authorization boundary, not production access control.

The server binds `127.0.0.1` by default and has **no authentication**. Anyone who can reach the port can drive the pipeline. Only set `WIENER_API_HOST=0.0.0.0` on a trusted, isolated network.

## 18. Project Status

Implemented: FastAPI API, Judge Mode, cloud/local/replay providers, Red AI loop, SOC/Blue/Risk/Policy pipeline, deterministic replay, tests, and simulated tools. Cloud and Ollama are the live-evaluation integrations; replay is offline setup verification. All tool execution and dashboard evidence are simulated/PoC artifacts. WIENER is not production-ready.

See [architecture](docs/architecture.md), [provider adapters](docs/PROVIDERS.md), [cloud route survey](docs/PROVIDER_SURVEY.md), [setup notes](docs/competition_setup.md), [demo runbook](docs/DEMO_RUNBOOK.md), [contracts](docs/contracts.md), and [benchmark notes](docs/BENCHMARK.md).

## 19. Evidence and Experiments

Three different things live in `data/experiments/`, and they are not
interchangeable. Confusing them is the fastest way to make an honest number
look dishonest.

| Directory | What it is | Status |
| --- | --- | --- |
| `authoritative_20260925_zero_degraded` | The 135-trial benchmark: 45 trials x 3 modes, live provider, locked artifacts. The source of the dashboard headline numbers. | Historical. Its `model` field records a transport name on 90 of 135 rows and no trial recorded its decoding temperature, so it does **not** satisfy the current validation checklist. Kept unmodified. |
| `authoritative_20260912_clean_2252` | The earlier 10-trial run. | Historical only. Its anomaly was not reproduced. |
| `enforcement_ablation_reference` | A separate experiment answering "is safety from the prompt or from the gate?" | Current, deterministic, offline. |

Regenerate the ablation (one command, no credentials, ~1 second):

```bash
python -m scripts.experiments.enforcement_ablation
```

It reports, for identical proposals and identical model output: with the gate
removed, every dangerous proposal is executed; with the gate enforced, none is;
benign proposals still pass; and the verdict does not change when the payload
contains an override instruction. The number that prevents execution is the
Policy Gate, not the prompt text.

The authoritative benchmark is a separate, much larger question (how often a
live model proposes something dangerous). Its two figures are UAR (unsafe
execution rate) and UAPR (unsafe action prevention rate). Read
[docs/BENCHMARK.md](docs/BENCHMARK.md) before quoting either: it states the
denominators, the Wilson intervals, and what the numbers do not establish.
