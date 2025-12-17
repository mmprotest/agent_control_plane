from __future__ import annotations

import logging
from typing import Any, Dict

import structlog


def setup_logging() -> None:
    timestamper = structlog.processors.TimeStamper(fmt="iso")
    pre_chain = [
        structlog.processors.add_log_level,
        timestamper,
    ]
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            timestamper,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=logging.INFO)


def log_event(event: str, **extra: Any) -> None:
    logger = structlog.get_logger()
    logger.info(event, **extra)
