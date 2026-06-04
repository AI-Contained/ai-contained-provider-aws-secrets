"""Account configuration models and loader for AWS secrets provider."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import json5

from ai_contained.provider.aws_secrets.types import AwsAccountId, LoginType, Role


@dataclass
class AccountLogin:
    """Login configuration for an AWS account."""

    type: LoginType
    command: str | None
    # Must exit non-zero on invalid credentials, and output JSON with an "Account" key on success.
    check_command: str | None = None
    fetch_command: str | None = None


@dataclass
class Account:
    """A configured AWS account with its access profiles and login method."""

    account_id: AwsAccountId
    name: str
    trust_groups: list[str]
    read_profile: str | None
    write_profile: str | None
    login: AccountLogin

    def profile_for(self, role: Role) -> str:
        """Return the AWS profile name for the given role, or raise if not configured."""
        profile = self.read_profile if role == Role.READ_ONLY else self.write_profile
        if profile is None:
            raise ValueError(f"no {role} profile configured for account {self.account_id}")
        return profile


def _parse_login(data: dict[str, Any], fallback: AccountLogin | None) -> AccountLogin:
    login_data = data.get("login", None)
    if login_data is not None:
        return AccountLogin(
            type=login_data["type"],
            command=login_data.get("command", None),
            check_command=login_data.get("check_command", None),
        )
    if fallback is not None:
        return fallback
    raise KeyError("Account has no login and no root login is defined")


class Accounts:
    """Collection of configured AWS accounts loaded from JSON5 config."""

    def __init__(self, config: str) -> None:
        """Parse accounts from JSON5 config string."""
        data = json5.loads(config)
        if "accounts" not in data:
            raise KeyError("Missing 'accounts' key in config")
        root_login = None
        if root_login_data := data.get("login", None):
            root_login = AccountLogin(
                type=root_login_data["type"],
                command=root_login_data.get("command", None),
                check_command=root_login_data.get("check_command", None),
            )
        self._accounts: dict[AwsAccountId, Account] = {
            account_id: Account(
                account_id=account_id,
                name=acct["name"],
                trust_groups=acct.get("trust_groups", []),
                read_profile=acct.get("read_profile", None),
                write_profile=acct.get("write_profile", None),
                login=_parse_login(acct, root_login),
            )
            for account_id, acct in data["accounts"].items()
        }

    def get_account(self, account_id: AwsAccountId) -> Account | None:
        """Return the account with the given ID, or None if not found."""
        return self._accounts.get(account_id, None)

    def get_group(self, group_name: str) -> list[Account]:
        """Return all non-disabled accounts belonging to the given trust group."""
        return [
            acct
            for acct in self._accounts.values()
            if group_name in acct.trust_groups and acct.login.type != "disabled"
        ]

    def all_accounts(self) -> list[Account]:
        """Return all non-disabled accounts."""
        return [acct for acct in self._accounts.values() if acct.login.type != "disabled"]


_accounts: Accounts | None = None


def load_aws_accounts(path: str) -> None:
    """Load accounts from the given config file path."""
    raise NotImplementedError


def get_aws_accounts() -> Accounts:
    """Return the globally loaded accounts instance."""
    raise NotImplementedError
