"""AWS Secrets provider for AI-Contained."""

import os

from fastmcp import FastMCP

from ai_contained.trust import server as trust_server

from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.credentials_manager import CredentialsManager
from ai_contained.provider.aws_secrets.aws_accounts_resource import AwsAccountsResource
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.aws_secret_route import AwsSecretRoute
from ai_contained.provider.aws_secrets.types import Role


_AUTH_READ_DESCRIPTION = """\
Authenticate to an AWS account with read-only access.

Use this tool to gain read-only access to an AWS account. It validates existing
credentials and prompts the user for consent; if valid credentials are already
present, no login flow is triggered.

Parameters
----------
  account_id  12-digit AWS account ID.
              Consult ai-contained://aws-secrets/accounts to discover available accounts and their IDs.

Return value (JSON):
  { "<account_id>": { "name": "<human name>", "expires_at": "<ISO 8601 timestamp or null>" } }

IMPORTANT — How to refer to accounts:
  - In conversation with the user, always use the human name (e.g. "Production"), never the
    account number — unless the user explicitly asks for it.
  - When calling this tool or any other tool that accepts an account_id, always pass the
    12-digit account number, never the human name.

Notes:
  - Prefer this over aws_auth_write — read-only access is safer and requires less privilege.
  - Authorization persists for the lifetime of the provider session.
"""


_AUTH_WRITE_DESCRIPTION = """\
Authenticate to an AWS account with read-write access.

Use this tool only when you need to create, update, or delete AWS resources.
It validates existing credentials and prompts the user for consent; if valid
credentials are already present, no login flow is triggered.

Parameters
----------
  account_id  12-digit AWS account ID.
              Consult ai-contained://aws-secrets/accounts to discover available accounts and their IDs.

Return value (JSON):
  { "<account_id>": { "name": "<human name>", "expires_at": "<ISO 8601 timestamp or null>" } }

IMPORTANT — How to refer to accounts:
  - In conversation with the user, always use the human name (e.g. "Production"), never the
    account number — unless the user explicitly asks for it.
  - When calling this tool or any other tool that accepts an account_id, always pass the
    12-digit account number, never the human name.

Notes:
  - Only use this when write access is genuinely required — prefer aws_auth_read otherwise.
  - Authorization persists for the lifetime of the provider session.
"""


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
    authenticator = CredentialsManager()
    auth_read = _auth_read or AwsAuthTool(Role.READ_ONLY, _accounts, authenticator)
    auth_write = _auth_write or AwsAuthTool(Role.READ_WRITE, _accounts, authenticator)

    # Bound methods hold a strong reference to self, keeping each component instance
    # (and the auth_read/auth_write it holds) alive for the lifetime of the server.
    mcp.add_resource(AwsAccountsResource(_accounts, auth_read, auth_write).get)
    mcp.tool(name="aws_auth_read", description=_AUTH_READ_DESCRIPTION)(auth_read.authenticate)
    mcp.tool(name="aws_auth_write", description=_AUTH_WRITE_DESCRIPTION)(auth_write.authenticate)

    aws_secret_route = AwsSecretRoute(auth_read, auth_write)
    trust_server.secret_route(mcp, role="aws")(aws_secret_route.handle)
