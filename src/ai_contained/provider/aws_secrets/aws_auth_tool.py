from fastmcp import Context, tools as mcp
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.credentials_manager import CredentialsManager, CredentialsManagerBase
from ai_contained.provider.aws_secrets.types import AwsAccountId, Role


class AwsAuthTool:
    def __init__(self, role: Role, accounts: Accounts, authenticator: CredentialsManagerBase = CredentialsManager()) -> None:
        self.role = role
        self.accounts = accounts
        self.authenticator = authenticator
        self._authorized: set[AwsAccountId] = set()

    def is_authorized(self, account_id: AwsAccountId) -> bool:
        return account_id in self._authorized

    def authorize(self, account_id: AwsAccountId) -> None:
        self._authorized.add(account_id)

    def revoke(self, account_id: AwsAccountId) -> None:
        self._authorized.discard(account_id)

    def revoke_all(self) -> None:
        self._authorized.clear()

    @mcp.tool()
    async def authenticate(self, ctx: Context, account_id: AwsAccountId) -> str:
        account = self.accounts.get_account(account_id)
        if account is None:
            raise ToolError(f"Unknown account: {account_id}")
        if not await self.authenticator.validate(self.role, account):
            await self.authenticator.login(ctx, self.role, account)
            if not await self.authenticator.validate(self.role, account):
                raise ToolError(f"Login succeeded but credentials are still invalid for {account_id}")
        self.authorize(account_id)
        return "ok"
