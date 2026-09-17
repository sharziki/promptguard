"""HTTP service for PromptGuard.

    uvicorn promptguard.server:app --port 8098
"""

from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import Action, Policy, PromptGuard, __version__

app = FastAPI(
    title="PromptGuard",
    version=__version__,
    description="Prompt-injection and jailbreak detection in ~170ms, powered by Jev.",
)

_guard: PromptGuard | None = None


def guard() -> PromptGuard:
    global _guard
    if _guard is None:
        if not os.environ.get("TYPESAFE_API_KEY"):
            raise HTTPException(503, "TYPESAFE_API_KEY is not configured on this server")
        _guard = PromptGuard()
    return _guard


class ScanRequest(BaseModel):
    text: str = Field(..., description="Untrusted user input to inspect")
    level: Literal["balanced", "strict", "paranoid"] = "balanced"


class BatchRequest(BaseModel):
    texts: list[str]
    level: Literal["balanced", "strict", "paranoid"] = "balanced"
    workers: int = 8


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__,
            "configured": bool(os.environ.get("TYPESAFE_API_KEY"))}


@app.post("/v1/scan")
def scan(req: ScanRequest) -> dict:
    try:
        return guard().scan(req.text, policy=Policy(level=req.level)).as_dict()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/v1/scan/batch")
def scan_batch(req: BatchRequest) -> dict:
    if not req.texts:
        raise HTTPException(422, "texts is empty")
    if len(req.texts) > 500:
        raise HTTPException(413, "batch limit is 500 texts")
    g = guard()
    pol = Policy(level=req.level)
    from concurrent.futures import ThreadPoolExecutor

    def one(t: str) -> dict:
        try:
            return g.scan(t, policy=pol).as_dict()
        except ValueError as exc:
            return {"error": str(exc)}

    with ThreadPoolExecutor(max_workers=min(req.workers, 16)) as pool:
        results = list(pool.map(one, req.texts))
    return {
        "results": results,
        "n": len(results),
        "blocked": sum(1 for r in results if r.get("action") == Action.BLOCK.value),
    }
