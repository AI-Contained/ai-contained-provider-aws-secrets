"""Credentials validation, login, and fetch logic for AWS accounts."""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Protocol, assert_never

from fastmcp import Context
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets.accounts import Account
from ai_contained.provider.aws_secrets.types import LoginType, Role


@dataclass
class Credential:
    """Short-lived AWS credential environment variables and their expiry."""

    env: dict[str, str]
    expiration: str | None


class CredentialsManagerBase(Protocol):
    """Protocol for pluggable credential backends (real AWS or test doubles)."""

    async def validate(self, role: Role, account: Account) -> bool:
        """Return True if credentials are valid; False if absent/expired; raise on wrong account."""
        ...

    async def login(self, ctx: Context, role: Role, account: Account) -> None:
        """Run the login flow; raise ToolError if unsupported, cancelled, or failed."""
        ...

    async def fetch_credentials(self, role: Role, account: Account) -> Credential:
        """Return current credentials; raise ToolError if unavailable."""
        ...


class CredentialsManager(CredentialsManagerBase):
    """Real AWS credentials manager that shells out to the AWS CLI."""

    async def validate(self, role: Role, account: Account) -> bool:
        """Check credentials via sts get-caller-identity (or check_command)."""
        command = account.login.check_command or "aws sts get-caller-identity --output json"
        proc = await asyncio.create_subprocess_shell(
            command,
            env={**os.environ, "AWS_PROFILE": account.profile_for(role)},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            return False
        try:
            caller = json.loads(stdout.decode())
            resolved = caller["Account"]
        except (json.JSONDecodeError, KeyError):
            raise ToolError(f"invalid response from check_command: {stdout.decode()!r}")
        if resolved != account.account_id:
            raise ToolError(f"credentials resolve to '{resolved}', expected '{account.account_id}'")
        return True

    async def fetch_credentials(self, role: Role, account: Account) -> Credential:
        """Export current credentials as env vars via the AWS CLI."""
        command = account.login.fetch_command or "aws configure export-credentials --format env"
        proc = await asyncio.create_subprocess_shell(
            command,
            env={**os.environ, "AWS_PROFILE": account.profile_for(role)},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise ToolError(f"credentials unavailable for {account.account_id}")
        env = {}
        for line in stdout.decode().splitlines():
            key, _, value = line.removeprefix("export ").partition("=")
            env[key] = value
        expiration = env.pop("AWS_CREDENTIAL_EXPIRATION", None)
        return Credential(env=env, expiration=expiration)

    async def login(self, ctx: Context, role: Role, account: Account) -> None:
        """Dispatch to the appropriate login flow for the account's login type."""
        match account.login.type:
            case LoginType.PREAUTH:
                raise ToolError("credentials invalid — fix externally and retry")
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
        command = account.login.command or "aws sso login --no-browser --use-device-code"

        proc = await asyncio.create_subprocess_shell(
            command,
            env={**os.environ, "AWS_PROFILE": account.profile_for(role)},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

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
            raise ToolError(
                json.dumps(
                    {
                        "exit_status": str(proc.returncode),
                        "stderr": (await proc.stderr.read()).decode(),
                        "stdout": "".join(captured_stdout),
                    }
                )
            )

        result = await ctx.elicit(message="".join(captured_stdout), response_type=None)
        if result.action != "accept":
            proc.kill()
            raise ToolError(f"The user has cancelled the login request to {account.name} ({account.account_id})")

        while proc.returncode is None:
            result = await ctx.elicit(message=loop_message, response_type=None)
            if result.action != "accept":
                proc.kill()
                raise ToolError(f"The user has cancelled the login request to {account.name} ({account.account_id})")

        if proc.returncode != 0:
            raise ToolError(
                json.dumps(
                    {
                        "exit_status": str(proc.returncode),
                        "stderr": (await proc.stderr.read()).decode(),
                        "stdout": "".join(captured_stdout),
                    }
                )
            )
