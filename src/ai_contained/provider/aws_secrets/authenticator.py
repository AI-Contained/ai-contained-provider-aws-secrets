import asyncio
import json
import os
from typing import Protocol, assert_never

from fastmcp import Context
from fastmcp.exceptions import ToolError

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
                await self._login_sso(ctx, role, account)

            case LoginType.DISABLED:
                raise NotImplementedError
            case LoginType.MFA:
                raise NotImplementedError
            case _ as unreachable:
                assert_never(unreachable)

    async def _login_sso(self, ctx: Context, role: Role, account: Account) -> None:
        loop_message = (
            "AWS SSO Login is still processing the authorization request.\n\n"
            "Click Allow to check again, or Decline to cancel."
        )
        profile = account.read_profile if role == Role.READ_ONLY else account.write_profile
        if not profile:
            raise AuthenticationError(
                f"No {role} profile configured for account {account.account_id}"
            )
        command = account.login.command or "aws sso login --no-browser --use-device-code"

        proc = await asyncio.create_subprocess_shell(
            command,
            env={**os.environ, "AWS_PROFILE": profile},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Two exit conditions: https_count == 2 (got both URLs, process still running)
        # or eof (process exited early — drain whatever stdout was buffered).
        https_count = 0
        captured_stdout = []
        eof = False
        while https_count < 2 and not eof:
            line = await proc.stdout.readline()
            eof = line == b""
            if not eof:
                decoded = line.decode()
                captured_stdout.append(decoded)
                if decoded.startswith("https://"):
                    https_count += 1

        if eof and https_count != 2:
            raise ToolError(json.dumps({
                "exit_status": str(proc.returncode),
                "stderr": (await proc.stderr.read()).decode(),
                "stdout": "".join(captured_stdout),
            }))

        result = await ctx.elicit(message="".join(captured_stdout), response_type=None)
        if result.action != "accept":
            proc.kill()
            raise ToolError(
                f"The user has cancelled the login request to {account.name} ({account.account_id})"
            )

        while proc.returncode is None:
            result = await ctx.elicit(message=loop_message, response_type=None)
            if result.action != "accept":
                proc.kill()
                raise ToolError(
                    f"The user has cancelled the login request to {account.name} ({account.account_id})"
                )

        if proc.returncode != 0:
            raise ToolError(json.dumps({
                "exit_status": str(proc.returncode),
                "stderr": (await proc.stderr.read()).decode(),
                "stdout": "".join(captured_stdout),
            }))
