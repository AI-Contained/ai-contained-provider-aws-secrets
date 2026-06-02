import dataclasses
from collections.abc import AsyncGenerator

import httpx
import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection
from ai_contained.trust.server.trust_store import get_trust_store

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.credentials_manager import Credential
from ai_contained.provider.aws_secrets.types import Role


def describe_AwsAuthTool():
    ACCOUNT_ID = "123456789012"

    def _return_responses(*values):
        it = iter(values)
        async def _fn(*args, **kwargs):
            val = next(it)
            if isinstance(val, Exception):
                raise val
            return val
        return _fn

    class MockCredentialsManager:
        async def validate(self, role, account):
            raise NotImplementedError("set mock_credentials_manager.validate = _return_responses(...)")

        async def login(self, ctx, role, account):
            raise NotImplementedError("set mock_credentials_manager.login = _return_responses(...)")

        async def fetch_credentials(self, role, account):
            raise NotImplementedError("set mock_credentials_manager.fetch_credentials = _return_responses(...)")

    @pytest.fixture
    def accounts() -> Accounts:
        return Accounts(f"""{{
            login: {{ type: "sso" }},
            accounts: {{ "{ACCOUNT_ID}": {{ name: "Test", read_profile: "test-read", write_profile: "test-write" }} }},
        }}""")

    def describe_is_authorized():
        def it_returns_false_by_default(aws_auth_read: AwsAuthTool) -> None:
            assert_that(aws_auth_read.is_authorized("123456789012")).is_false()

        def it_returns_false_after_revoke(aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.authorize("123456789012")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_true()
            aws_auth_read.revoke("123456789012")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_false()

        def it_returns_false_after_revoke_all(aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.authorize("123456789012")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_true()
            aws_auth_read.revoke_all()
            assert_that(aws_auth_read.is_authorized("123456789012")).is_false()

        def it_is_idempotent_when_authorizing_twice(aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.authorize("123456789012")
            aws_auth_read.authorize("123456789012")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_true()

    def describe_revoke():
        def it_does_not_raise_when_revoking_unknown_account(aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.revoke("123456789012")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_false()

        def it_only_revokes_target_account(aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.authorize("123456789012")
            aws_auth_read.authorize("456789012345")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_true()
            assert_that(aws_auth_read.is_authorized("456789012345")).is_true()
            aws_auth_read.revoke("123456789012")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_false()
            assert_that(aws_auth_read.is_authorized("456789012345")).is_true()

        def it_revoke_all_clears_all_accounts(aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.authorize("123456789012")
            aws_auth_read.authorize("456789012345")
            assert_that(aws_auth_read.is_authorized("123456789012")).is_true()
            assert_that(aws_auth_read.is_authorized("456789012345")).is_true()
            aws_auth_read.revoke_all()
            assert_that(aws_auth_read.is_authorized("123456789012")).is_false()
            assert_that(aws_auth_read.is_authorized("456789012345")).is_false()

    def describe_authenticate():
        @pytest.fixture
        async def auth_setup(accounts: Accounts):
            mock_credentials_manager = MockCredentialsManager()
            auth_tool = AwsAuthTool(Role.READ_ONLY, accounts, mock_credentials_manager)
            mcp = FastMCP("test")
            await register(mcp, _accounts=accounts, _auth_read=auth_tool)
            async with Client(transport=mcp) as c:
                yield c, auth_tool, mock_credentials_manager

        async def it_registers_aws_auth_read_and_aws_auth_write_tools() -> None:
            mcp = FastMCP("test")
            accounts = Accounts("""
            {
                login: { type: "sso" },
                accounts: { "123456789012": { name: "Test", read_profile: "test-read" } },
            }
            """)
            await register(mcp, _accounts=accounts)
            tool_names = [t.name for t in await mcp.list_tools()]
            assert_that(tool_names).contains("aws_auth_read", "aws_auth_write")

        async def it_authorizes_when_already_validated(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(True)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_logs_in_when_not_validated(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(False, True)
            mock_credentials_manager.login = _return_responses(None)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_raises_when_post_login_validation_fails(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(False, False)
            mock_credentials_manager.login = _return_responses(None)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(f"Login succeeded but credentials are still invalid for {ACCOUNT_ID}")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        async def it_raises_when_account_is_unknown(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            result = await client.call_tool("aws_auth_read", {"account_id": "000000000000"}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("Unknown account: 000000000000")

        async def it_raises_when_login_raises_tool_error(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(False)
            mock_credentials_manager.login = _return_responses(ToolError("user cancelled"))
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("user cancelled")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        async def it_skips_login_when_credentials_are_still_valid(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(True, True)
            first = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(first.is_error).is_false()
            second = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_re_logs_in_when_credentials_expire(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(True, False, True)
            mock_credentials_manager.login = _return_responses(None)
            first = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(first.is_error).is_false()
            second = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_raises_when_validate_raises_an_error(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(ToolError("wrong account"))
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        async def it_raises_when_post_login_validate_raises_an_error(auth_setup) -> None:
            client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = _return_responses(False, ToolError("wrong account"))
            mock_credentials_manager.login = _return_responses(None)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

    def describe_secret_route():
        @pytest.fixture
        async def secret_setup(accounts: Accounts) -> AsyncGenerator:
            mock_credentials_manager = MockCredentialsManager()
            auth_read = AwsAuthTool(Role.READ_ONLY, accounts, mock_credentials_manager)
            auth_write = AwsAuthTool(Role.READ_WRITE, accounts, mock_credentials_manager)

            # trust_server
            get_trust_store().reset()
            trust_server.get_trust_config().reset("127.0.0.1")
            mcp = FastMCP("test")
            await trust_server.register(mcp)

            # aws-secrets
            await register(mcp, _accounts=accounts, _auth_read=auth_read, _auth_write=auth_write)

            # trust_client
            transport = httpx.ASGITransport(app=mcp.http_app(), client=("127.0.0.1", 50000))
            async with httpx.AsyncClient(transport=transport, base_url="http://ignored") as http:
                conn = TrustConnection(http)
                await conn.register()
                yield TrustClient(_connection=conn, _path="/aws/secret"), auth_read, auth_write, mock_credentials_manager

        async def it_returns_credentials_when_authorized(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            expected = Credential(
                env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                expiration="2026-06-01T11:12:44+00:00",
            )
            auth_read.authorize(ACCOUNT_ID)
            mock_credentials_manager.fetch_credentials = _return_responses(expected)
            result = await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
            assert_that(result).is_equal_to({ACCOUNT_ID: dataclasses.asdict(expected)})

        async def it_returns_credentials_with_no_expiration(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            expected = Credential(
                env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                expiration=None,
            )
            auth_read.authorize(ACCOUNT_ID)
            mock_credentials_manager.fetch_credentials = _return_responses(expected)
            result = await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
            assert_that(result).is_equal_to({ACCOUNT_ID: dataclasses.asdict(expected)})

        async def it_returns_not_authorized_when_account_not_authorized(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
            assert_that(exc_info.value.response.status_code).is_equal_to(403)
            assert_that(exc_info.value.response.json()["code"]).is_equal_to("NOT_AUTHORIZED")

        async def it_returns_unknown_account_when_account_not_found(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.post({"account_id": "000000000000", "role": "ReadOnly"})
            assert_that(exc_info.value.response.status_code).is_equal_to(404)
            assert_that(exc_info.value.response.json()["code"]).is_equal_to("UNKNOWN_ACCOUNT")

        async def it_returns_session_expired_when_credentials_unavailable(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            auth_read.authorize(ACCOUNT_ID)
            mock_credentials_manager.fetch_credentials = _return_responses(ToolError("credentials unavailable"))
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
            assert_that(exc_info.value.response.status_code).is_equal_to(401)
            assert_that(exc_info.value.response.json()["code"]).is_equal_to("SESSION_EXPIRED")

        async def it_returns_invalid_request_for_unknown_role(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.post({"account_id": ACCOUNT_ID, "role": "SuperAdmin"})
            assert_that(exc_info.value.response.status_code).is_equal_to(400)
            assert_that(exc_info.value.response.json()["code"]).is_equal_to("INVALID_REQUEST")

        async def it_uses_write_auth_for_read_write_role(secret_setup) -> None:
            client, auth_read, auth_write, mock_credentials_manager = secret_setup
            expected = Credential(
                env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                expiration=None,
            )
            auth_write.authorize(ACCOUNT_ID)
            mock_credentials_manager.fetch_credentials = _return_responses(expected)
            result = await client.post({"account_id": ACCOUNT_ID, "role": "ReadWrite"})
            assert_that(result).is_equal_to({ACCOUNT_ID: dataclasses.asdict(expected)})
