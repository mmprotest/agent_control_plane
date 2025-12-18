from __future__ import annotations

import datetime as dt
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class PolicyExplanation(BaseModel):
    decision: str = Field(description="Final decision after evaluation")
    matched_rule_id: Optional[str] = None
    matched_rule_index: Optional[int] = None
    specificity_score: int = 0
    matched_selectors: Dict[str, Any] = Field(default_factory=dict)
    triggered_constraints: Dict[str, Any] = Field(default_factory=dict)
    evaluation_timestamp: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    policy_sha: Optional[str] = None
    policy_version: Optional[str] = None

    class Config:
        json_encoders = {dt.datetime: lambda v: v.isoformat()}
