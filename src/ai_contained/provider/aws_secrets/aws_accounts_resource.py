from __future__ import annotations

from dataclasses import dataclass

from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import AccessStatus, AwsAccountId


@dataclass
class AwsAccountResourceEntry:
    name: str
    trust_groups: list[str]
    read_only: AccessStatus
    read_write: AccessStatus


class AwsAccountsResource:
    def __init__(self, accounts: Accounts, auth_read: AwsAuthTool, auth_write: AwsAuthTool) -> None:
        self._accounts = accounts
        self._auth_read = auth_read
        self._auth_write = auth_write

    def _access_status(self, account_id: AwsAccountId, auth: AwsAuthTool, aws_profile: str | None) -> AccessStatus:
        if aws_profile is None:
            return AccessStatus.UNSUPPORTED
        elif auth.is_authorized(account_id):
            return AccessStatus.AUTHORIZED
        return AccessStatus.REQUIRES_AUTH

    def get(self) -> dict[AwsAccountId, AwsAccountResourceEntry]:
        return {
            account.account_id: AwsAccountResourceEntry(
                name=account.name,
                trust_groups=account.trust_groups,
                read_only=self._access_status(account.account_id, self._auth_read, account.read_profile),
                read_write=self._access_status(account.account_id, self._auth_write, account.write_profile),
            )
            for account in self._accounts.all_accounts()
        }
