from __future__ import annotations

from ai_contained.provider.aws_secrets.types import AwsAccountId, Role


class AwsAuthTool:
    def __init__(self, role: Role) -> None:
        raise NotImplementedError

    def is_authorized(self, account_id: AwsAccountId) -> bool:
        raise NotImplementedError

    def authorize(self, account_id: AwsAccountId) -> None:
        raise NotImplementedError

    def revoke(self, account_id: AwsAccountId) -> None:
        raise NotImplementedError

    def revoke_all(self) -> None:
        raise NotImplementedError
