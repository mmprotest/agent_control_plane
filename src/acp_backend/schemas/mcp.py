from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class McpRegisterRequest(BaseModel):
    base_url: str
    tools: Optional[List[str]] = Field(default=None, description="Filter tool names")


class McpRegisterResponse(BaseModel):
    registered: List[str]
    discovered: List[Dict[str, Any]]


class McpToolListing(BaseModel):
    tools: List[Dict[str, Any]]
