import pytest
from fastmcp import FastMCP


@pytest.fixture
def mcp() -> FastMCP:
    return FastMCP("test")
