import pytest
from fastmcp import FastMCP

from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role


@pytest.fixture
def mcp() -> FastMCP:
    return FastMCP("test")


@pytest.fixture
def aws_auth_read() -> AwsAuthTool:
    return AwsAuthTool(Role.READ_ONLY, Accounts('{ login: { type: "sso" }, accounts: {} }'))


@pytest.fixture
def aws_auth_write() -> AwsAuthTool:
    return AwsAuthTool(Role.READ_WRITE, Accounts('{ login: { type: "sso" }, accounts: {} }'))
