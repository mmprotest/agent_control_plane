from __future__ import annotations

from fastapi import FastAPI

app = FastAPI()


@app.get("/mcp/tools")
async def list_tools():
    return {
        "tools": [
            {"name": "echo", "schema": {"type": "object", "properties": {"text": {"type": "string"}}}},
            {"name": "blocked", "schema": {}},
            {"name": "add", "schema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}},
        ]
    }


@app.post("/mcp/tools/echo")
async def echo(payload: dict):
    return {"echo": payload}


@app.post("/mcp/tools/blocked")
async def blocked(payload: dict):
    return {"error": "blocked", "payload": payload}


@app.post("/mcp/tools/add")
async def add(payload: dict):
    a = payload.get("a", 0)
    b = payload.get("b", 0)
    return {"sum": a + b}
