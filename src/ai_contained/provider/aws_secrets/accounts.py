from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import json5


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


def _parse_login(data: dict, fallback: AccountLogin | None) -> AccountLogin:
    login_data = data.get("login")
    if login_data is not None:
        return AccountLogin(type=login_data["type"], command=login_data.get("command"))
    if fallback is not None:
        return fallback
    raise KeyError("Account has no login and no root login is defined")


class Accounts:
    def __init__(self, config: str) -> None:
        data = json5.loads(config)
        if "accounts" not in data:
            raise KeyError("Missing 'accounts' key in config")
        root_login = None
        if root_login_data := data.get("login"):
            root_login = AccountLogin(type=root_login_data["type"], command=root_login_data.get("command"))
        self._accounts: dict[str, Account] = {
            account_id: Account(
                account_id=account_id,
                name=acct["name"],
                trust_groups=acct.get("trust_groups", []),
                read_profile=acct.get("read_profile"),
                write_profile=acct.get("write_profile"),
                login=_parse_login(acct, root_login),
            )
            for account_id, acct in data["accounts"].items()
        }

    def get_account(self, account_id: str) -> Account | None:
        return self._accounts.get(account_id)

    def get_group(self, group_name: str) -> list[Account]:
        return [
            acct for acct in self._accounts.values()
            if group_name in acct.trust_groups and acct.login.type != "disabled"
        ]

    def all_accounts(self) -> list[Account]:
        return [
            acct for acct in self._accounts.values()
            if acct.login.type != "disabled"
        ]


_accounts: Accounts | None = None


def load_aws_accounts(path: str) -> None:
    raise NotImplementedError


def get_aws_accounts() -> Accounts:
    raise NotImplementedError
