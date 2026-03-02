#!/usr/bin/env python3
"""Entry point for the Automaite Linux server agent."""

import asyncio
import logging
import os
import signal
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stdout,
)

logger = logging.getLogger("agent.run")


async def main():
    relay_url = os.environ.get("RELAY_URL", "ws://localhost:8080/ws/agent")
    agent_key = os.environ.get("AGENT_KEY", "")

    if not agent_key:
        logger.error("AGENT_KEY environment variable is required")
        sys.exit(1)

    logger.info("Starting agent — relay=%s", relay_url)

    from agent import run
    await run(relay_url, agent_key)


if __name__ == "__main__":
    asyncio.run(main())
