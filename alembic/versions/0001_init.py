"""initial schema"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "role",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String, unique=True, nullable=False),
        sa.Column("permissions", sa.JSON, nullable=False, server_default="[]"),
    )
    op.create_table(
        "agent",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("hashed_api_key", sa.String, nullable=False),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("role.id")),
    )
    op.create_table(
        "user",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String, nullable=False),
        sa.Column("hashed_token", sa.String, nullable=False),
        sa.Column("role_id", sa.Integer, sa.ForeignKey("role.id")),
    )
    op.create_table(
        "tool",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("type", sa.String, nullable=False),
        sa.Column("endpoint", sa.String),
        sa.Column("requires_approval", sa.Boolean, server_default=sa.false(), nullable=False),
        sa.Column("allowed_domains", sa.JSON, server_default="[]"),
    )
    op.create_table(
        "approvalrequest",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("approval_id", sa.String, nullable=False),
        sa.Column("agent_id", sa.Integer, sa.ForeignKey("agent.id")),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("user.id")),
        sa.Column("tool_name", sa.String, nullable=False),
        sa.Column("status", sa.String, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("token", sa.String, nullable=False),
        sa.Column("approved_by", sa.String),
    )
    op.create_table(
        "auditlogentry",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("action", sa.String, nullable=False),
        sa.Column("agent_id", sa.Integer),
        sa.Column("user_id", sa.Integer),
        sa.Column("tool_name", sa.String),
        sa.Column("decision", sa.String, nullable=False),
        sa.Column("details", sa.JSON, nullable=False),
        sa.Column("prev_hash", sa.String, nullable=False),
        sa.Column("current_hash", sa.String, nullable=False),
        sa.Column("trace_id", sa.String),
    )
    op.create_table(
        "trace",
        sa.Column("trace_id", sa.String, primary_key=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("agent_id", sa.Integer),
        sa.Column("user_id", sa.Integer),
        sa.Column("tool_name", sa.String, nullable=False),
        sa.Column("request_payload", sa.JSON, nullable=False),
        sa.Column("redacted_request", sa.JSON, nullable=False),
        sa.Column("response_payload", sa.JSON, nullable=False),
        sa.Column("redacted_response", sa.JSON, nullable=False),
        sa.Column("policy_decision", sa.JSON, nullable=False),
        sa.Column("execution_details", sa.JSON, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("trace")
    op.drop_table("auditlogentry")
    op.drop_table("approvalrequest")
    op.drop_table("tool")
    op.drop_table("user")
    op.drop_table("agent")
    op.drop_table("role")
