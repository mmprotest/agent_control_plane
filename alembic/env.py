from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

from acp_backend.models.base import SQLModelBase
from acp_backend.database import get_engine

config = context.config
fileConfig(config.config_file_name)

target_metadata = SQLModelBase.metadata

def run_migrations_offline() -> None:
    url = os.getenv("DATABASE_URL")
    if url is None:
        raise RuntimeError("DATABASE_URL not set for offline migrations")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = get_engine()
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
