<<<<<<< HEAD
from typing import Any

from assertpy import assert_that
from fastmcp.client.elicitation import ElicitRequestParams, ElicitResult
from mcp.client.session import ClientSession
from mcp.shared.context import RequestContext

from ai_contained.core.mcp.harness import Harness
from ai_contained.core.mcp.testing import Elicitor


class LocalHarness(Harness):
    """Harness with the aws-secrets auth tools callable directly.

    Authorization happens the real way — the tool call with an accepted
    elicitation — and the tool's parsed response is returned for assertions.
    """

    async def aws_auth_read(self, account_id: str) -> Any:
        """Call the aws_auth_read tool for the account, accepting its elicitation."""
        return await self._run_auth_tool("aws_auth_read", account_id)

    async def aws_auth_write(self, account_id: str) -> Any:
        """Call the aws_auth_write tool for the account, accepting its elicitation."""
        return await self._run_auth_tool("aws_auth_write", account_id)

    async def _run_auth_tool(self, tool: str, account_id: str) -> Any:
        self.elicit.accept()
        async with self.client() as c:
            result = await c.tool(tool)(account_id=account_id)
            assert_that(result.is_error).is_false()
            return result.json()


# The number of loop elicitations in _login_sso is non-deterministic: on slower CI
# machines the subprocess exit event may not have been processed by asyncio before
# proc.returncode is checked, causing one extra loop elicitation beyond what the test
# registered. Tests affected by this apply the patch below via monkeypatch to silently
# accept when the queue is exhausted rather than crashing the MCP session.
_upstream_elicitor_call = Elicitor.__call__


async def with_accept_fallback(
    self: Elicitor,
    message: str,
    response_type: type | None,
    params: ElicitRequestParams,
    context: RequestContext[ClientSession, Any],
) -> ElicitResult:
    try:
        return await _upstream_elicitor_call(self, message, response_type, params, context)
    except IndexError:
        return ElicitResult(action="accept", content=None)


class MockCredentialsManager:
    async def validate(self, role, account):
        raise NotImplementedError("set mock_credentials_manager.validate = return_responses(...)")

    async def login(self, ctx, role, account):
        raise NotImplementedError("set mock_credentials_manager.login = return_responses(...)")

    async def fetch_credentials(self, role, account):
        raise NotImplementedError("set mock_credentials_manager.fetch_credentials = return_responses(...)")


def return_responses(*values):
    it = iter(values)

    async def _fn(*args, **kwargs):
        val = next(it)
        if isinstance(val, Exception):
            raise val
        return val

    return _fn
