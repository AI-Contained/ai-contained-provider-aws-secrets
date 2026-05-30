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
        raise NotImplementedError

    def get(self) -> dict[AwsAccountId, AwsAccountResourceEntry]:
        raise NotImplementedError
