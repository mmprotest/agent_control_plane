from __future__ import annotations

from sqlmodel import SQLModel


class SQLModelBase(SQLModel):
    class Config:
        arbitrary_types_allowed = True
        populate_by_name = True
        json_encoders = {}
