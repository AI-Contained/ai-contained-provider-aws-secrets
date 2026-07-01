"""Credentials validation, login, and fetch logic for AWS accounts."""

import asyncio
import json
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol, assert_never

from fastmcp import Context
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets.accounts import Account
from ai_contained.provider.aws_secrets.types import LoginType, Role


@dataclass
class Credential:
    """Short-lived AWS credential environment variables and their expiry."""

    name: str
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

    def _aws_env(self, **overrides: str) -> dict[str, str]:
        """Build the environment for AWS subprocesses.

        AWS CLI has no env var to relocate ~/.aws/ wholesale (aws/aws-cli#9031),
        so pin HOME to keep config, credentials, and SSO cache on the bind mount.
        HOME is redirected to AWS_HOME if set, else to dirname(AWS_ACCOUNTS_CONFIG_PATH)
        if set, else left as the container's HOME.
        """
        env = {**os.environ, **overrides}
        aws_home = os.environ.get("AWS_HOME") or (
            os.path.dirname(config_path) if (config_path := os.environ.get("AWS_ACCOUNTS_CONFIG_PATH")) else None
        )
        if aws_home:
            env["HOME"] = aws_home
        return env

    @staticmethod
    @asynccontextmanager
    async def managed_shell(cmd: str, **kwargs: Any) -> AsyncGenerator[asyncio.subprocess.Process, None]:
        """Run a shell command and guarantee cleanup on exit.

        Yields the Process. On exit (normal or exception), sends SIGTERM and
        waits up to 5 seconds; escalates to SIGKILL if the process doesn't stop.
        """
        proc = await asyncio.create_subprocess_shell(cmd, **kwargs)
        try:
            yield proc
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()

    async def validate(self, role: Role, account: Account) -> bool:
        """Check credentials via sts get-caller-identity (or check_command)."""
        command = account.login.check_command or "aws sts get-caller-identity --output json"
        async with self.managed_shell(
            command,
            env=self._aws_env(AWS_PROFILE=account.profile_for(role)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        ) as proc:
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
        async with self.managed_shell(
            command,
            env=self._aws_env(AWS_PROFILE=account.profile_for(role)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        ) as proc:
            stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise ToolError(f"credentials unavailable for {account.account_id}")
        env = {}
        for line in stdout.decode().splitlines():
            key, _, value = line.removeprefix("export ").partition("=")
            env[key] = value
        expiration = env.pop("AWS_CREDENTIAL_EXPIRATION", None)
        return Credential(name=account.name, env=env, expiration=expiration)

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

        async with self.managed_shell(
            command,
            env=self._aws_env(AWS_PROFILE=account.profile_for(role)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        ) as proc:
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
                raise ToolError(f"The user has cancelled the login request to {account.name} ({account.account_id})")

            while proc.returncode is None:
                result = await ctx.elicit(message=loop_message, response_type=None)
                if result.action != "accept":
                    raise ToolError(
                        f"The user has cancelled the login request to {account.name} ({account.account_id})"
                    )
                await asyncio.sleep(0)

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
