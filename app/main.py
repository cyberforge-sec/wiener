from __future__ import annotations

from fastapi import FastAPI

from .api.routes import router
from .config import config
from .llm.factory import active_provider_name

app = FastAPI(title="WIENER", version="0.1.0")
app.include_router(router)


@app.on_event("startup")
def _log_provider() -> None:
    print(f"[wiener] active provider tier: {active_provider_name()}")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)


if __name__ == "__main__":
    main()
