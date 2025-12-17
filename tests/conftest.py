from __future__ import annotations

from typing import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from acp_backend.api.main import app, get_db_session
from acp_backend.core.security import hash_secret
from acp_backend.models.entities import Agent, Role, Tool, User


def create_test_engine():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture()
def session() -> Iterator[Session]:
    engine = create_test_engine()
    with Session(engine) as session:
        role = Role(name="operator", permissions=["echo", "sum_numbers"])
        session.add(role)
        session.commit()
        session.refresh(role)
        agent = Agent(name="agent", hashed_api_key=hash_secret("test-key"), role_id=role.id)
        user = User(email="user@test.com", hashed_token=hash_secret("user-token"), role_id=role.id)
        session.add(agent)
        session.add(user)
        session.add(Tool(name="echo", type="internal", requires_approval=False))
        session.add(Tool(name="sum_numbers", type="internal", requires_approval=True))
        session.add(Tool(name="secret_fetch", type="internal", requires_approval=False))
        session.commit()
        yield session


@pytest.fixture()
def client(session: Session) -> TestClient:
    async def _get_session():
        yield session

    app.dependency_overrides[get_db_session] = _get_session
    return TestClient(app)
