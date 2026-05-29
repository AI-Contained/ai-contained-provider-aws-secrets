from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class AccountLogin:
    type: Literal["sso", "preauth", "disabled", "mfa"]
    command: str | None


@dataclass
class Account:
    account_id: str
    name: str
    trust_groups: list[str]
    read_profile: str | None
    write_profile: str | None
    login: AccountLogin


class Accounts:
    def __init__(self, config: str) -> None:
        raise NotImplementedError

    def get_account(self, account_id: str) -> Account | None:
        raise NotImplementedError

    def get_group(self, group_name: str) -> list[Account] | None:
        raise NotImplementedError

    def all_accounts(self) -> list[Account]:
        raise NotImplementedError


_accounts: Accounts | None = None


def load_aws_accounts(path: str) -> None:
    raise NotImplementedError


def get_aws_accounts() -> Accounts:
    raise NotImplementedError
