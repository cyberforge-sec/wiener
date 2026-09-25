# WIENER Competition Setup

This is the concise evaluator setup reference. The root [README](../README.md)
is the authoritative command-by-command guide.

## Native verification

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
WIENER_LLM_FORCE=replay ./run_healthcheck
WIENER_LLM_FORCE=replay ./run_replay --scenario ALL --validate --runs 3
WIENER_LLM_FORCE=replay python -m app.main
```

Open `http://localhost:8000/judge` and use provider `replay` for an offline
setup smoke test. The API health endpoint is `/health`. Replay verifies the
installation only; it is not the required live competition evaluation.

The first-run `.env` is intentionally safe: `WIENER_CLOUD_API_KEY` is empty
and `WIENER_LLM_FORCE=replay`. Before the live evaluation, change
`WIENER_LLM_FORCE` to `opencode` or `local` and verify `/health` reports that
provider. Do not put a placeholder API key in `.env`; a non-empty key is
treated as a real cloud configuration.

## Provider configuration

Cloud is one of the two required live-evaluation paths and is supplied by the
evaluator through `.env`. OpenCode is not required: direct OpenAI and any
OpenAI-compatible provider/gateway work with the existing cloud adapter. Use
the provider-neutral `WIENER_CLOUD_*` variables; the old `WIENER_OPENCODE_*`
names are compatibility fallbacks only:

```env
# Leave blank until a real evaluator-provided key is available.
WIENER_CLOUD_API_KEY=
WIENER_CLOUD_BASE_URL=https://api.openai.com/v1
WIENER_CLOUD_MODEL=gpt-4o-mini
WIENER_LLM_FORCE=opencode
```

Replace the base URL and model when using a different OpenAI-compatible
provider. The legacy internal name for this mode is `opencode`; OpenCode is not
required.

For an existing `.env`, rename every `WIENER_OPENCODE_*` variable to its
matching `WIENER_CLOUD_*` name, then restart the native server or rebuild and
restart the Docker image. The old names still work as compatibility fallbacks.

Ollama is the second required live-evaluation path. It is required when
selecting the built-in local provider because that provider calls Ollama's
`/api/generate` API. Start it in one terminal, then pull and verify it from a
second terminal:

```bash
# Terminal 1
ollama serve

# Terminal 2
ollama pull qwen2.5:1.5b
curl http://localhost:11434/api/tags
```

Configure the local connection in `.env`:

```env
WIENER_LLM_FORCE=local
WIENER_LOCAL_HOST=http://localhost:11434
WIENER_LOCAL_MODEL=qwen2.5:1.5b
WIENER_LOCAL_TIMEOUT_S=60
WIENER_LOCAL_MAX_TOKENS=128
WIENER_LOCAL_KEEP_ALIVE=5m
```

`WIENER_LOCAL_HOST` is the Ollama HTTP endpoint, while
`WIENER_LOCAL_MODEL` is the model tag returned by `ollama pull`. Other local
runtimes are not direct backends in this release. With neither live provider
available, replay remains a setup fallback, not a live result.

## Docker

Offline replay is the safe setup smoke test, not the live evaluation path:

```bash
docker build -t wiener:local .
docker run --rm -p 8000:8000 -e WIENER_LLM_FORCE=replay wiener:local
```

For live cloud, configure a real key in `.env` first, then select the cloud
adapter explicitly:

```bash
docker run --rm -p 8000:8000 --env-file .env -e WIENER_LLM_FORCE=opencode wiener:local
```

For host Ollama, `localhost` is not valid inside the container. Use the host
address and select local mode explicitly:

```bash
docker run --rm -p 8000:8000 --add-host=host.docker.internal:host-gateway -e WIENER_LLM_FORCE=local -e WIENER_LOCAL_HOST=http://host.docker.internal:11434 wiener:local
```

## Safety statement

Every action is simulated. The Policy Gate is the final deterministic decision
layer; no API path performs a real account, endpoint, network, or firewall
change.
