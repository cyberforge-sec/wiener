# WIENER

WIENER is a sandboxed AI-vs-AI security proof of concept for evaluating how a policy-controlled SOC workflow responds to adversarial and ambiguous alerts. It is a HackNusa 2026 submission, not a production security-control plane.

## 1. What is WIENER?

An LLM-assisted SOC Agent may propose an action from untrusted alert text. WIENER separates that **proposal** from **execution authority**: the SOC Agent proposes, while a deterministic Risk Engine and Policy Gate decide whether the simulated tool layer may act. Red AI provides adversarial input and Blue AI evaluates the resulting trajectory.

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
`replay`. `opencode` is only the legacy internal identifier for the cloud
option; it does **not** require an OpenCode account or model. The UI reports
the tier actually used.

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

### Choose a run mode

The repository does not include your API key or local model. Choose one mode:

| Goal | What you provide | `WIENER_LLM_FORCE` |
| --- | --- | --- |
| Offline evaluation | Nothing beyond the application | `replay` |
| Live cloud inference | Your own OpenAI-compatible key, base URL, and model | `opencode` |
| Live local inference | Ollama and a model installed on the same machine | `local` |
| Automatic selection | Optional cloud and/or local configuration | empty |

`opencode` is the legacy internal name for the cloud adapter; the UI labels it
**Cloud (OpenAI-compatible)**. The checked-in `.env.example` is safe: its cloud
key is empty and its default is `replay`.

## 6. Quick Start

The first run is intentionally offline and deterministic. It uses no API key,
no Ollama, and no network call:

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
run a scenario. Stop the server with `Ctrl+C`. The copied `.env` is safe: its
cloud key is empty and its provider default is `replay`.

To use a live model, edit `.env` using the Cloud or Local section below. To
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

The command above is the safest first run. Visit `http://localhost:8000/judge`
or call `/health` in another terminal. If port 8000 is busy, use `-p 8001:8000`.

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
docker run --rm -p 8000:8000 --env-file .env -e WIENER_LLM_FORCE=opencode wiener:local
```

For local Ollama in Docker, use the host gateway command in section 10. If a
cloud run fails inside Docker, the local fallback also needs that host gateway;
otherwise WIENER falls through to replay. Never bake `.env`, keys, or models
into the image; `.dockerignore` excludes secrets, logs, and cache.

## 9. Cloud LLM Setup

The cloud adapter uses an OpenAI-compatible chat-completions API. **OpenCode
is not required.** Use direct OpenAI credentials or any provider/gateway that
implements compatible `chat/completions`. The documented variables are
`WIENER_CLOUD_*`; legacy `WIENER_OPENCODE_*` variables remain accepted only
for backwards compatibility. Copy `.env.example` to `.env`, then replace the
cloud key and, if needed, the URL/model with values belonging to the evaluator:

```env
# Leave blank until you have a real key. Do not use a placeholder value.
WIENER_CLOUD_API_KEY=
WIENER_CLOUD_BASE_URL=https://api.openai.com/v1
WIENER_CLOUD_MODEL=gpt-4o-mini
WIENER_LLM_FORCE=opencode
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
docker run --rm -p 8000:8000 --env-file .env -e WIENER_LLM_FORCE=opencode wiener:local
```

The old names remain accepted for backward compatibility, so this migration is
recommended for clarity, not an emergency breaking change.

| Cloud choice | Works now? | Notes |
| --- | --- | --- |
| OpenAI API | Yes | Configure its standard `/v1` base URL, key, and model. |
| Any OpenAI-compatible provider/gateway | Yes | Configure that service's compatible base URL, key, and model. |
| OpenCode | Optional | It is one possible compatible service, not a requirement. |
| Native Anthropic or Gemini API | Not directly | Use an OpenAI-compatible gateway, or add a dedicated provider adapter. |

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
Local inference is optional; replay remains available without it. Other local
runtimes (LM Studio, vLLM, llama.cpp, LocalAI) are not direct local-provider
backends in this release unless they expose an Ollama-compatible API.

| Local choice | Works now? | Notes |
| --- | --- | --- |
| Ollama | Yes | Required for the built-in `local` provider; choose any Ollama model that can return the required JSON. |
| No local runtime | Yes | Use cloud or deterministic replay instead. |
| LM Studio, vLLM, llama.cpp, LocalAI | Not directly | Add an adapter, or expose an Ollama-compatible endpoint. |

## 11. Replay Mode

Replay uses the recorded response store and makes no cloud or Ollama request:

```bash
./run_replay --scenario ALL
./run_replay --scenario ALL --validate --runs 3
```

It is deterministic/offline verification, not live LLM inference. Generated
replay run files are intentionally ignored by Git. This is the recommended
mode for an evaluator who does not have an API key or Ollama.

## 12. Judge Mode

Start the server and open `/judge`. For a first evaluation choose **Replay**.
For live inference choose **Cloud** (legacy internal API value: `opencode`) or
**Local (Ollama)**; these are alternatives, not two models that must run
together. Choose `normal`, `prompt_injection`, or `adaptive`, then select
**Run**. **Replay** repeats the latest request and **Reset** clears state.
Evaluators should inspect the actual provider tier, pipeline stages, policy
verdict, and simulated-tool result.

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

```bash
python -m pytest -q
WIENER_LLM_FORCE=replay ./run_healthcheck
WIENER_LLM_FORCE=replay ./run_replay --scenario ALL --validate --runs 3
```

The health check reports unavailable cloud/Ollama as warnings because replay is a supported fallback.

## 15. Verification

- [ ] Application starts and `/health` returns `ok`.
- [ ] Replay scenarios are deterministic.
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

## 18. Project Status

Implemented: FastAPI API, Judge Mode, cloud/local/replay providers, Red AI loop, SOC/Blue/Risk/Policy pipeline, deterministic replay, tests, and simulated tools. Cloud and Ollama are optional evaluator-supplied integrations. All tool execution and dashboard evidence are simulated/PoC artifacts. WIENER is not production-ready.

See [architecture](docs/architecture.md), [setup notes](docs/competition_setup.md), [demo runbook](docs/DEMO_RUNBOOK.md), [contracts](docs/contracts.md), and [benchmark notes](docs/BENCHMARK.md).
