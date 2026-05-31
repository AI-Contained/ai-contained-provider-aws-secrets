from typing import Protocol, assert_never

from fastmcp import Context

from ai_contained.provider.aws_secrets.accounts import Account
from ai_contained.provider.aws_secrets.types import LoginType, Role


class AuthenticationError(Exception):
    pass


class AuthenticatorBase(Protocol):
    async def validate(self, role: Role, account: Account) -> bool:
        # Returns True if credentials are valid and resolve to account.account_id.
        # Returns False if credentials are absent or expired.
        # Raises AuthenticationError if credentials are valid but resolve to the wrong account.
        ...

    async def login(self, ctx: Context, role: Role, account: Account) -> None:
        # Runs the login flow for the given login type and validates afterward.
        # Raises AuthenticationError if login is unsupported, user cancels, or post-login validation fails.
        ...


class Authenticator(AuthenticatorBase):
    async def validate(self, role: Role, account: Account) -> bool:
        profile = account.read_profile if role == Role.READ_ONLY else account.write_profile
        # 1. run: aws sts get-caller-identity --profile <profile>
        # 2. non-zero exit → return False
        # 3. parse JSON, extract Account field
        # 4. account mismatch → raise AuthenticationError
        # 5. return True
        raise NotImplementedError

    async def login(self, ctx: Context, role: Role, account: Account) -> None:
        match account.login.type:
            case LoginType.PREAUTH:
                raise AuthenticationError("credentials invalid — fix externally and retry")
            case LoginType.SSO:
                # 1. run account.login.command via sh -c with AWS_PROFILE=<profile> injected (stdin=DEVNULL)
                # 2. capture stdout (the SSO URL)
                # 3. send elicitation: show URL + "Login complete? Allow?"
                # 4. declined → raise AuthenticationError("user cancelled")
                # 5. accepted → call validate(); if still invalid raise AuthenticationError("login succeeded but credentials still invalid")
                raise NotImplementedError
            case LoginType.DISABLED:
                raise NotImplementedError
            case LoginType.MFA:
                raise NotImplementedError
            case _ as unreachable:
                assert_never(unreachable)
