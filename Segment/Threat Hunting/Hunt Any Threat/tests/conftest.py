"""
Pytest configuration and shared fixtures for ZeroThreatHuntTools tests.
"""

# pylint: disable=W0621
import os
from pathlib import Path
from typing import Generator

import pytest
from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]

from src.zero_threat_hunt_tools import ZeroThreatHuntTools


def load_env_file() -> None:
    """
    Load environment variables from .env file.

    Looks for .env file in the project root directory (Hunt Any Threat).
    """
    # Get the project root (Hunt Any Threat directory)
    project_root = Path(__file__).parent.parent
    env_file = project_root / ".env"

    if env_file.exists():
        load_dotenv(env_file)
    else:
        # Try parent directory if .env is not in project root
        parent_env = project_root.parent / ".env"
        if parent_env.exists():
            load_dotenv(parent_env)


@pytest.fixture(scope="session")
def api_key() -> str:
    """
    Load API key from environment variable.

    Loads ZN_API_KEY from .env file using python-dotenv.

    :return: Zero Networks API key
    :rtype: str
    :raises ValueError: If ZN_API_KEY is not set in environment
    """

    api_key = os.getenv("ZN_API_KEY", None)

    if not api_key:
        # Load .env file
        load_env_file()

        # Get API key from environment
        api_key = os.getenv("ZN_API_KEY")

    if not api_key or len(api_key.strip()) == 0:
        raise ValueError(
            "ZN_API_KEY environment variable is not set or empty. "
            "Please create a .env file in the project root with ZN_API_KEY=your-api-key"
        )

    return api_key.strip()


@pytest.fixture
def threat_hunt_tools(api_key: str) -> Generator[ZeroThreatHuntTools, None, None]:
    """
    Create a ZeroThreatHuntTools instance for testing.

    :param api_key: Zero Networks API key from api_key fixture
    :type api_key: str
    :yield: ZeroThreatHuntTools instance
    :rtype: Generator[ZeroThreatHuntTools, None, None]
    """
    tools = ZeroThreatHuntTools(api_key=api_key)
    yield tools
