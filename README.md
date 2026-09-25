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

## 6. Quick Start

```bash
git clone https://github.com/cyberforge-sec/wiener.git
cd wiener
python3 -m venv .venv
. .venv/bin/activate                 # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cp .env.example .env
./run_replay --scenario ALL
python -m app.main
```

Open `http://localhost:8000/judge`. The replay command needs no credentials or local model. Stop the server with `Ctrl+C`.

## 7. Run Without Docker

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
./run_healthcheck
WIENER_LLM_FORCE=replay python -m app.main
```

In another terminal, verify `curl http://localhost:8000/health` and run:

```bash
curl -X POST http://localhost:8000/judge/run -H 'content-type: application/json' -d '{"provider":"replay","scenario":"normal"}'
```

The health response should be `ok`; the Judge response identifies `replay`. Remove `WIENER_LLM_FORCE` to restore automatic cloud → local → replay selection.

## 8. Run With Docker

```bash
docker build -t wiener:local .
docker run --rm -p 8000:8000 -e WIENER_LLM_FORCE=replay wiener:local
```

Visit `http://localhost:8000/judge` or call `/health`. The image has a Docker health check; inspect it with `docker inspect --format '{{.State.Health.Status}}' <container-id>`. Use `docker logs <container-id>`, `docker stop <container-id>`, and a new `docker run` command to view logs, stop, and restart. If port 8000 is busy, use `-p 8001:8000`.

For cloud mode, keep credentials in a local `.env` and pass it explicitly:

```bash
docker run --rm -p 8000:8000 --env-file .env wiener:local
```

Never bake `.env`, keys, or models into the image; `.dockerignore` excludes secrets, logs, and cache.

## 9. Cloud LLM Setup

The cloud adapter uses an OpenAI-compatible chat-completions API. **OpenCode
is not required.** Use direct OpenAI credentials or any provider/gateway that
implements compatible `chat/completions`; the `WIENER_OPENCODE_*` environment
variable names are retained only for backwards compatibility. Copy
`.env.example` to `.env` and insert credentials belonging to the evaluator:

```env
WIENER_OPENCODE_API_KEY=your_api_key_here
WIENER_OPENCODE_BASE_URL=https://your-provider.example/v1
WIENER_OPENCODE_MODEL=your_supported_model
WIENER_LLM_TIMEOUT_S=30
```

`WIENER_OPENCODE_TEMPERATURE` and `WIENER_OPENCODE_RESPONSE_FORMAT` are optional. An empty key skips cloud; an unavailable cloud tier falls to local then replay. Do not commit `.env`.

## 10. Local LLM Setup (Ollama)

The local provider currently calls the Ollama HTTP API (`/api/generate`), so
**Ollama is required if you select local mode**. It is not required for cloud
or replay mode. For a native local run, install/start Ollama and pull the
selected model:

```bash
ollama serve
ollama pull qwen2.5:1.5b
curl http://localhost:11434/api/tags
```

Configure `WIENER_LOCAL_HOST`, `WIENER_LOCAL_MODEL`, `WIENER_LOCAL_TIMEOUT_S`, `WIENER_LOCAL_MAX_TOKENS`, and `WIENER_LOCAL_KEEP_ALIVE`. Docker Desktop should use `http://host.docker.internal:11434`; on Linux add the host gateway mapping:

```bash
docker run --rm -p 8000:8000 --add-host=host.docker.internal:host-gateway -e WIENER_LOCAL_HOST=http://host.docker.internal:11434 -e WIENER_LOCAL_MODEL=qwen2.5:1.5b wiener:local
```

`localhost` inside a container means the container itself, not host Ollama.
Local inference is optional; replay remains available without it. Other local
runtimes (LM Studio, vLLM, llama.cpp, LocalAI) are not direct local-provider
backends in this release unless they expose an Ollama-compatible API.

## 11. Replay Mode

Replay uses the recorded response store and makes no cloud or Ollama request:

```bash
./run_replay --scenario ALL
./run_replay --scenario ALL --validate --runs 3
```

It is deterministic/offline verification, not live LLM inference. Generated replay run files are intentionally ignored by Git.

## 12. Judge Mode

Start the server and open `/judge`. Choose **Cloud** (internal API value:
`opencode`), **Local (Ollama)**, or `replay`; choose `normal`,
`prompt_injection`, or `adaptive`; then select **Run**. **Replay** repeats the
latest request and **Reset** clears state. Evaluators should inspect the actual
provider tier, pipeline stages, policy verdict, and simulated-tool result.

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
./run_healthcheck
./run_replay --scenario ALL --validate --runs 3
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
| Invalid cloud URL | Provider API root is incorrect. | Set its OpenAI-compatible base URL, normally ending `/v1`. |
| Container cannot reach Ollama | Container localhost differs from host localhost. | Use `host.docker.internal:11434`; Linux also needs `--add-host=host.docker.internal:host-gateway`. |
| Dependency install fails | Unsupported Python or unavailable package index. | Use Python 3.10+, recreate venv, restore package-index access. |

## 17. Security Notes

Never commit `.env`, API keys, tokens, provider diagnostics, runtime logs, or environments. Diagnostic capture is disabled by default because responses can be sensitive. The Policy Gate is a simulation authorization boundary, not production access control.

## 18. Project Status

Implemented: FastAPI API, Judge Mode, cloud/local/replay providers, Red AI loop, SOC/Blue/Risk/Policy pipeline, deterministic replay, tests, and simulated tools. Cloud and Ollama are optional evaluator-supplied integrations. All tool execution and dashboard evidence are simulated/PoC artifacts. WIENER is not production-ready.

See [architecture](docs/architecture.md), [setup notes](docs/competition_setup.md), [demo runbook](docs/DEMO_RUNBOOK.md), [contracts](docs/contracts.md), and [benchmark notes](docs/BENCHMARK.md).
