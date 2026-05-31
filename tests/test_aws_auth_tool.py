import pytest
from assertpy import assert_that
from fastmcp import FastMCP

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role


def describe_AwsAuthTool():
    @pytest.fixture
    def aws_auth_read() -> AwsAuthTool:
        return AwsAuthTool(Role.READ_ONLY, Accounts('{ login: { type: "sso" }, accounts: {} }'))

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
