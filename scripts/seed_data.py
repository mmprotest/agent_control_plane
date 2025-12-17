from __future__ import annotations

from acp_backend.core.security import hash_secret
from acp_backend.database import get_session, init_db
from acp_backend.models.entities import Agent, Role, Tool, User


def seed() -> None:
    init_db()
    with get_session() as session:
        operator_role = Role(name="operator", permissions=["echo", "sum_numbers"])
        session.add(operator_role)
        session.commit()
        session.refresh(operator_role)

        agent = Agent(name="demo-agent", hashed_api_key=hash_secret("demo-key"), role_id=operator_role.id)
        user = User(email="user@example.com", hashed_token=hash_secret("user-token"), role_id=operator_role.id)
        session.add(agent)
        session.add(user)

        echo_tool = Tool(name="echo", type="internal", requires_approval=False)
        sum_tool = Tool(name="sum_numbers", type="internal", requires_approval=True)
        session.add(echo_tool)
        session.add(sum_tool)

        session.commit()
        print("Seeded demo data: agent api key=demo-key, user token=user-token")


if __name__ == "__main__":
    seed()
