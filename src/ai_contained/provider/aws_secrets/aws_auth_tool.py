from fastmcp import Context
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.authenticator import Authenticator, AuthenticatorBase
from ai_contained.provider.aws_secrets.types import AwsAccountId, Role


class AwsAuthTool:
    def __init__(self, role: Role, accounts: Accounts, authenticator: AuthenticatorBase = Authenticator()) -> None:
        self.role = role
        self._accounts = accounts
        self._authenticator = authenticator
        self._authorized: set[AwsAccountId] = set()

    def is_authorized(self, account_id: AwsAccountId) -> bool:
        return account_id in self._authorized

    def authorize(self, account_id: AwsAccountId) -> None:
        self._authorized.add(account_id)

    def revoke(self, account_id: AwsAccountId) -> None:
        self._authorized.discard(account_id)

    def revoke_all(self) -> None:
        self._authorized.clear()

    async def authenticate(self, ctx: Context, account_id: AwsAccountId) -> str:
        raise NotImplementedError
