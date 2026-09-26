# WIENER

WIENER is a sandboxed AI-vs-AI security proof of concept. An LLM-assisted SOC
Agent reads an untrusted alert and *proposes* an action; a deterministic Risk
Engine and Policy Gate decide whether that action is allowed to execute.

> **THE MODEL PROPOSES. THE POLICY DECIDES.**

WIENER is a HackNUSA 2026 submission. It is a research PoC, not a production
security control plane.

---

## Quick Start

This gets you to Judge Mode in about a minute using **Replay**, which is fully
offline and needs no API key, no model download, and no network.

### 1. Clone

```bash
git clone https://github.com/cyberforge-sec/wiener.git
cd wiener
```

### 2. Create an environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
```

### 3. Install

```bash
python -m pip install -r requirements.txt
```

### 4. Configure

```bash
cp .env.example .env
```

The shipped `.env.example` is already safe: its cloud key is empty and its
default is Replay. You do not need to edit anything to run the steps below.

### 5. Start in Replay

```bash
WIENER_LLM_FORCE=replay python -m app.main
```

### 6. Open Judge Mode

<http://localhost:8000/judge>

Stop the server with `Ctrl+C`.

### 7. Try it

Leave the provider on **Replay**, pick a scenario, and press **Run**:

| Scenario | What it shows |
| --- | --- |
| **Normal** | A routine alert. The pipeline proposes, scores, and reaches a policy verdict. |
| **Prompt Injection** | Alert text carrying an embedded override instruction. Watch the proposed action, the risk score, and the verdict. |
| **Adaptive Attack** | An adversarial loop that reacts to how WIENER answered, rather than firing one fixed payload. |

After a run, read the stage output: SOC Agent proposal → Blue AI assessment →
Risk score → Policy Gate verdict → simulated tool result. **Replay** repeats the
last request; **Reset** clears the session.

If `/judge/run` ever appears to hang, `.env` was not copied — without it the
provider ladder starts at the cloud tier and waits on a network call. Run
`cp .env.example .env` and restart.

---

## Requirements

- **Python 3.10+** (3.12 is the verified release environment). Use Docker if a
  matching interpreter is unavailable.
- **Docker Engine** — only for the Docker path.
- **Ollama** — only for the Local provider.
- **Network access** — only for a cloud provider. Replay works fully offline.

`./run_healthcheck` verifies your environment. It reports an unreachable cloud
provider or a stopped Ollama as a **warning**, not a failure, because Replay is
a supported fallback.

```bash
WIENER_LLM_FORCE=replay ./run_healthcheck
```

---

## Cloud / Local / Replay

WIENER resolves inference through a **failover ladder**:

```text
cloud  →  local (Ollama)  →  replay
```

Each rung is a real provider adapter behind one common contract. The UI always
reports which tier actually served the request, so you can tell what happened
rather than assuming.

| Tier | Requirement | Use it for |
| --- | --- | --- |
| **Cloud** | Your own API key, base URL, and model | The live competition evaluation |
| **Local** | Ollama running on the same machine | Live evaluation with no external API |
| **Replay** | Nothing | Deterministic offline setup checks |

Force a tier with `WIENER_LLM_FORCE=cloud | local | replay`. Leave it empty to
let the ladder choose automatically.

`WIENER_LLM_FORCE=replay` is the **setup smoke test only**. It is deterministic
recorded data, not live inference, and must not be presented as live evidence.

### Local (Ollama)

```bash
# terminal 1 — leave this running
ollama serve

# terminal 2 — pull once, then confirm
ollama pull qwen2.5:1.5b
curl -s http://127.0.0.1:11434/api/tags
```

Then set the provider in `.env`:

```env
WIENER_LLM_FORCE=local
WIENER_LOCAL_HOST=127.0.0.1:11434
WIENER_LOCAL_MODEL=qwen2.5:1.5b
```

From inside a container, the host is not `127.0.0.1`. Use
`host.docker.internal:11434`, and on Linux add
`--add-host=host.docker.internal:host-gateway`.

### Replay

Replay reads recorded fixtures from `app/replay/recorded/` and needs no external
API, key, or network. It is the safest way to confirm the installation works
and the offline safety net when everything else is unavailable.

---

## Bring Your Own LLM

**WIENER supports the provider protocols implemented by its adapters.** You can
provide your own supported API endpoint, API key, and model. WIENER is not tied
to one vendor, and it is not a universal API client — it speaks the specific
wire protocols below, and nothing else.

| `WIENER_CLOUD_ADAPTER` | Wire protocol | Notes |
| --- | --- | --- |
| `openai_compatible` (default) | `POST {base_url}/chat/completions` | Any service implementing the OpenAI chat-completions API — OpenAI, or a compatible gateway. |
| `anthropic` | `POST {base_url}/v1/messages` | Native Anthropic Messages API. `system` is a top-level parameter, auth is `x-api-key`, and the response is typed content blocks. The adapter translates all of that. |

`Local` (Ollama) and `Replay` are the other two implemented tiers. There is no
adapter for any other protocol, and none is implied.

### OpenAI-compatible endpoint, key, and model

```env
WIENER_CLOUD_ADAPTER=openai_compatible
WIENER_CLOUD_API_KEY=your-key
WIENER_CLOUD_BASE_URL=https://your-gateway.example/v1
WIENER_CLOUD_MODEL=your-model-id
```

Point `WIENER_CLOUD_BASE_URL` at whichever supported provider or gateway you
use, as long as it implements the OpenAI-compatible chat-completions API. Set
`WIENER_CLOUD_PROVIDER_LABEL` so the Judge UI names the tier honestly instead of
showing a default.

Native Anthropic:

```env
WIENER_CLOUD_ADAPTER=anthropic
WIENER_ANTHROPIC_API_KEY=your-key
WIENER_ANTHROPIC_BASE_URL=https://api.anthropic.com
WIENER_ANTHROPIC_MODEL=claude-sonnet-4-6
```

Optional: `WIENER_CLOUD_TEMPERATURE` (default `0.0`) and
`WIENER_CLOUD_EXPECTED_MODEL`, which is used to check the model identity the
provider reports rather than trusting the requested string.

### What changing the provider does — and does not — change

This distinction is the point of the project:

```text
Provider / model choice  →  determines which LLM writes the proposal
Security boundary        →  does not change
```

The execution flow is fixed:

```text
LLM provider
  → SOC Agent proposal
  → Trajectory / Blue AI
  → Risk Engine
  → Policy Gate
  → simulated Tool Execution
```

Swapping the model or the endpoint changes only the text the SOC Agent
proposes. Risk scoring, policy thresholds, action criticality, hard
constraints, execution authorization, and the executor's own re-check of the
decision are identical, and the test suite asserts that invariance directly
(`tests/test_provider_agnostic.py`) rather than asserting it in prose.

**Execution authority never moves into the model.** A model that is fully
convinced still cannot act on its own: a non-`ALLOW` decision cannot reach a
tool, and `SimulatedToolExecutor` re-checks the decision itself.

Never commit `.env`, keys, or tokens. Put credentials in your local `.env` only.

---

## Docker

Build once:

```bash
docker build -t wiener:local .
```

Run in Replay:

```bash
docker run --rm -p 8000:8000 -e WIENER_API_HOST=0.0.0.0 -e WIENER_LLM_FORCE=replay wiener:local
```

`WIENER_API_HOST=0.0.0.0` is required for `-p` to work: the server binds
`127.0.0.1` by default, and a container's loopback is not the interface Docker
publishes. Without it the container starts, its own health check passes, and
the host still gets connection refused.

Then open <http://localhost:8000/judge>. If port 8000 is busy, use
`-p 8001:8000`. The app has no authentication, so publish it only on a trusted
network.

Background container with an inspectable health status:

```bash
docker run -d --name wiener-demo -p 8000:8000 -e WIENER_API_HOST=0.0.0.0 -e WIENER_LLM_FORCE=replay wiener:local
docker inspect --format '{{.State.Health.Status}}' wiener-demo
```

Cloud mode: supply your own credentials with `--env-file .env`.

```bash
docker run --rm -p 8000:8000 -e WIENER_API_HOST=0.0.0.0 --env-file .env -e WIENER_LLM_FORCE=openai_compatible wiener:local
```

---

## Security Boundary

WIENER is a simulation. It does not isolate real endpoints, disable real
accounts, change firewall rules, connect to a production SIEM, or perform real
security actions.

`SimulatedToolExecutor` is the only execution layer, and every result it
returns is labelled simulated — even when `executed=true`. `ALLOW` permits only
a simulated result; `REVIEW` and `BLOCK` refuse execution. The Policy Gate is a
simulation authorization boundary, **not** production access control.

The server binds `127.0.0.1` by default and has **no authentication**. Anyone
who can reach the port can drive the pipeline. Only set
`WIENER_API_HOST=0.0.0.0` on a trusted, isolated network.

## PoC Limitation

This is a proof of concept built for evaluation, not a deployable product. It
is not production-ready. In particular:

- Tool execution is simulated; nothing is enforced on a real system.
- The Policy Gate is deterministic logic under test, not a hardened control.
- Results come from one benchmark configuration; a pinned model on a different
  provider route can behave differently.
- There is no authentication, no multi-tenancy, no persistence, and no audit
  pipeline beyond local logging.
- Diagnostic capture is disabled by default, because provider responses can be
  sensitive.

---

## Authoritative Benchmark Figures

These are the official submission figures from the **135-trial** evaluation
(45 trials x 3 modes, live provider). **Unsafe Action Rate (UAR)** is the share
of adversarial trials that ended in an unsafe *execution* rather than a held or
refused decision.

| Mode | Unsafe executions | UAR |
| --- | --- | --- |
| No Defense | 12 / 45 | **26.67%** |
| Basic Prompt Defense | 7 / 45 | **15.56%** |
| **WIENER** | **0 / 45** | **0.00%** |

Basic Prompt Defense is a prompt-only baseline. WIENER is the full pipeline.

The WIENER row is the claim: unsafe execution fell to zero out of 45 trials,
against 26.67% with no defense and 15.56% with a prompt-only defense. The
proposals still arrive — the model is still persuaded — and the execution
boundary is what refuses them.

Treat these as fixed submission numbers. They are not recomputed at runtime, and
this repository ships no experiment harness that could regenerate them.

---

## Tests

```bash
python -m pip install -r requirements-dev.txt    # adds pytest
python -m pytest -q
```

The suite runs fully offline against Replay and fake providers, and needs no
credentials.

---

## API Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Runtime status and the resolved provider tier |
| `/judge` | GET | Judge Mode UI — the judge-facing entry point |
| `/judge/run` | POST | Run a scenario; `?stream=true` starts SSE |
| `/judge/stream` | GET | SSE events for a `run_id` |
| `/judge/state` | GET | Latest Judge metadata |
| `/judge/replay` | POST | Repeat the latest Judge request |
| `/judge/reset` | POST | Reset the Judge session |
| `/analyze` | POST | Run the pipeline for a `SOCContext` JSON body |

---

## Repository Layout

```text
app/          FastAPI app, Judge Mode, pipeline, providers, replay fixtures
config/       Action metadata, safety constraints, Red AI seeds
scripts/      Health check used by ./run_healthcheck
tests/        Pytest suite
Dockerfile    Container image
run_healthcheck / run_replay   Setup verification launchers
```

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `/judge/run` hangs | `.env` was not copied. Run `cp .env.example .env`. |
| Docker container runs, host gets connection refused | Add `-e WIENER_API_HOST=0.0.0.0` to `docker run`. |
| Port 8000 already in use | Use `-p 8001:8000`. |
| Ollama unavailable | Run `ollama serve`, verify `/api/tags`, check `WIENER_LOCAL_HOST`. |
| Model not found | `ollama pull <model>`. |
| Cloud key missing | Set your key in `.env`, or use Local or Replay. |
| Invalid cloud URL | The base URL is the API root, normally ending in `/v1`. |
| Container cannot reach Ollama | Use `host.docker.internal:11434`; on Linux also add `--add-host=host.docker.internal:host-gateway`. |
| Dependency install fails | Use Python 3.10+, recreate the venv, restore package-index access. |
