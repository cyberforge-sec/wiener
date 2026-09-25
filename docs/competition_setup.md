# WIENER Competition Setup

This is the concise evaluator setup reference. The root [README](../README.md)
is the authoritative command-by-command guide.

## Native verification

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
./run_healthcheck
./run_replay --scenario ALL --validate --runs 3
WIENER_LLM_FORCE=replay python -m app.main
```

Open `http://localhost:8000/judge` and use provider `replay` for an offline,
deterministic evaluation. The API health endpoint is `/health`.

## Provider configuration

Cloud is optional and is supplied by the evaluator through `.env`. OpenCode is
not required: direct OpenAI and any OpenAI-compatible provider/gateway work
with the existing cloud adapter. Use the provider-neutral `WIENER_CLOUD_*`
variables; the old `WIENER_OPENCODE_*` names are compatibility fallbacks only:

```env
WIENER_CLOUD_API_KEY=your_api_key_here
WIENER_CLOUD_BASE_URL=https://your-provider.example/v1
WIENER_CLOUD_MODEL=your_supported_model
```

For an existing `.env`, rename every `WIENER_OPENCODE_*` variable to its
matching `WIENER_CLOUD_*` name, then restart the native server or rebuild and
restart the Docker image. The old names still work as compatibility fallbacks.

Ollama is optional for the overall application, but it is required when using
the built-in local provider because that provider calls Ollama's
`/api/generate` API. Start it, pull a selected model, and configure
`WIENER_LOCAL_HOST`, `WIENER_LOCAL_MODEL`, timeout, token limit, and keep-alive
variables from `.env.example`. Other local runtimes are not direct backends in
this release. With neither cloud nor Ollama available, replay is a supported
deterministic fallback.

## Docker

```bash
docker build -t wiener:local .
docker run --rm -p 8000:8000 -e WIENER_LLM_FORCE=replay wiener:local
```

For host Ollama, `localhost` is not valid inside the container. Use
`WIENER_LOCAL_HOST=http://host.docker.internal:11434`; on Linux also pass
`--add-host=host.docker.internal:host-gateway`.

## Safety statement

Every action is simulated. The Policy Gate is the final deterministic decision
layer; no API path performs a real account, endpoint, network, or firewall
change.
