from __future__ import annotations

from ai_contained.provider.aws_secrets.types import AwsAccountId, Role


class AwsAuthTool:
    def __init__(self, role: Role) -> None:
        self.role = role
        self._authorized: set[AwsAccountId] = set()

    def is_authorized(self, account_id: AwsAccountId) -> bool:
        return account_id in self._authorized

    def authorize(self, account_id: AwsAccountId) -> None:
        self._authorized.add(account_id)

    def revoke(self, account_id: AwsAccountId) -> None:
        self._authorized.discard(account_id)

    def revoke_all(self) -> None:
        self._authorized.clear()
