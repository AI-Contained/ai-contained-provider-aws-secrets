import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from fastmcp.client import Client

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role
from fastmcp.exceptions import ToolError


def describe_AwsAuthTool():
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
        ACCOUNT_ID = "123456789012"

        def _return_responses(*values):
            it = iter(values)
            async def _fn(*args, **kwargs):
                val = next(it)
                if isinstance(val, Exception):
                    raise val
                return val
            return _fn

        class MockAuthenticator:
            async def validate(self, role, account):
                raise NotImplementedError("set mock.validate = _return_responses(...)")

            async def login(self, ctx, role, account):
                raise NotImplementedError("set mock.login = _return_responses(...)")

        @pytest.fixture
        def accounts() -> Accounts:
            return Accounts(f"""{{
                login: {{ type: "sso" }},
                accounts: {{ "{ACCOUNT_ID}": {{ name: "Test", read_profile: "test-read" }} }},
            }}""")

        @pytest.fixture
        async def auth_setup(accounts: Accounts):
            mock = MockAuthenticator()
            auth_tool = AwsAuthTool(Role.READ_ONLY, accounts, mock)
            mcp = FastMCP("test")
            await register(mcp, _accounts=accounts, _auth_read=auth_tool)
            async with Client(transport=mcp) as c:
                yield c, auth_tool, mock

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
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(True)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_logs_in_when_not_validated(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(False, True)
            mock.login = _return_responses(None)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_raises_when_post_login_validation_fails(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(False, False)
            mock.login = _return_responses(None)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(f"Login succeeded but credentials are still invalid for {ACCOUNT_ID}")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        async def it_raises_when_account_is_unknown(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            result = await client.call_tool("aws_auth_read", {"account_id": "000000000000"}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("Unknown account: 000000000000")

        async def it_raises_when_login_raises_tool_error(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(False)
            mock.login = _return_responses(ToolError("user cancelled"))
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("user cancelled")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        async def it_skips_login_when_credentials_are_still_valid(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(True, True)
            first = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(first.is_error).is_false()
            second = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_re_logs_in_when_credentials_expire(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(True, False, True)
            mock.login = _return_responses(None)
            first = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(first.is_error).is_false()
            second = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

        async def it_raises_when_validate_raises_an_error(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(ToolError("wrong account"))
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        async def it_raises_when_post_login_validate_raises_an_error(auth_setup) -> None:
            client, auth_tool, mock = auth_setup
            mock.validate = _return_responses(False, ToolError("wrong account"))
            mock.login = _return_responses(None)
            result = await client.call_tool("aws_auth_read", {"account_id": ACCOUNT_ID}, raise_on_error=False)
            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()
