"""MCP tool implementation for AWS account authentication."""

import hashlib
from typing import Any

from fastmcp import Context
from fastmcp import tools as mcp
from fastmcp.exceptions import ToolError

from ai_contained.core.mcp import Environ
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.credentials_manager import CredentialsManagerBase
from ai_contained.provider.aws_secrets.types import AwsAccountId, Role


class _Color:
    """ANSI colorizer for elicitation messages. Disabled via COLOR != 'ascii'."""

    def __init__(self, environ: Environ) -> None:
        """Read the COLOR toggle once from the given environment."""
        self._enabled = environ.get("COLOR", "ascii") == "ascii"

    def _wrap(self, ansi: str, text: str) -> str:
        if not self._enabled:
            return text
        return f"\033[{ansi}m{text}\033[0m"

    def role(self, name: str) -> str:
        """Green for aws_auth_read, red for aws_auth_write."""
        return self._wrap("32" if name == "aws_auth_read" else "31", name)

    def id(self, account: str) -> str:
        """Dim gray — de-emphasizes the 12-digit account ID next to its human name."""
        return self._wrap("38;5;245", account)

    def name(self, account_name: str) -> str:
        """Deterministic per-name hue, hashed into the 6×6×6 color cube (codes 17–231)."""
        code = (hashlib.blake2b(account_name.encode(), digest_size=1).digest()[0] % 215) + 17
        return self._wrap(f"38;5;{code}", account_name)


class AwsAuthTool:
    """Manages per-account authorization state and drives the authenticate MCP tool."""

    def __init__(
        self,
        environ: Environ,
        authenticator: CredentialsManagerBase,
        role: Role,
        accounts: Accounts,
    ) -> None:
        """Initialise from the container's launch env with a credentials manager, for the given role."""
        self.role = role
        self.accounts = accounts
        self.authenticator = authenticator
        self._color = _Color(environ)
        self._authorized: set[AwsAccountId] = set()

    def is_authorized(self, account_id: AwsAccountId) -> bool:
        """Return True if the account has been authorized this session."""
        return account_id in self._authorized

    def authorize(self, account_id: AwsAccountId) -> None:
        """Mark an account as authorized."""
        self._authorized.add(account_id)

    def revoke(self, account_id: AwsAccountId) -> None:
        """Remove authorization for an account."""
        self._authorized.discard(account_id)

    def revoke_all(self) -> None:
        """Remove authorization for all accounts."""
        self._authorized.clear()

    @mcp.tool()
    async def authenticate(self, ctx: Context, account_id: AwsAccountId) -> dict[str, Any]:
        """Authenticate to an AWS account and return short-lived credentials."""
        account = self.accounts.get_account(account_id)
        if account is None:
            raise ToolError(
                f"Unknown account: {account_id}. "
                "Consult ai-contained://aws-secrets/accounts to discover available accounts and their IDs."
            )
        if not self.is_authorized(account_id):
            role_label = "ReadOnly" if self.role == Role.READ_ONLY else "ReadWrite"
            tool_name = "aws_auth_read" if self.role == Role.READ_ONLY else "aws_auth_write"
            result = await ctx.elicit(
                message=(
                    f"I'd like {role_label} AWS Access to {self._color.name(account.name)}"
                    f"({self._color.id(account_id)}). (using tool: {self._color.role(tool_name)})"
                ),
                response_type=None,
            )
            if result.action != "accept":
                raise ToolError(f"Access to {tool_name}({account.name}) was declined")
        if not await self.authenticator.validate(self.role, account):
            await self.authenticator.login(ctx, self.role, account)
            if not await self.authenticator.validate(self.role, account):
                raise ToolError(f"Login succeeded but credentials are still invalid for {account_id}")
        self.authorize(account_id)
        credential = await self.authenticator.fetch_credentials(self.role, account)
        return {account_id: {"name": account.name, "expires_at": credential.expiration}}
