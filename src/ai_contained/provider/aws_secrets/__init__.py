"""AWS Secrets provider for AI-Contained."""

import os

from fastmcp import FastMCP

from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_accounts_resource import AwsAccountsResource
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role


async def register(
    mcp: FastMCP,
    *,
    _accounts: Accounts | None = None,      # test injection only — overrides AWS_ACCOUNTS_CONFIG_PATH
    _auth_read: AwsAuthTool | None = None,   # test injection only — overrides default AwsAuthTool
    _auth_write: AwsAuthTool | None = None,  # test injection only — overrides default AwsAuthTool
) -> None:
    """Register all AWS secrets provider tools with the MCP server."""
    if _accounts is None:
        config_path = os.environ.get("AWS_ACCOUNTS_CONFIG_PATH")
        if not config_path:
            return
        _accounts = Accounts(open(config_path).read())

    # auth_read and auth_write are shared across all components — the same instances
    # are passed to every resource and tool so that authorize() called by one is
    # immediately visible to is_authorized() called by another.
    auth_read = _auth_read or AwsAuthTool(Role.READ_ONLY)
    auth_write = _auth_write or AwsAuthTool(Role.READ_WRITE)

    # Bound methods hold a strong reference to self, keeping each component instance
    # (and the auth_read/auth_write it holds) alive for the lifetime of the server.
    mcp.add_resource(AwsAccountsResource(_accounts, auth_read, auth_write).get)
