import json
from dataclasses import dataclass


import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.credentials_manager import Credential
from ai_contained.provider.aws_secrets.types import Role

from conftest import MockCredentialsManager, return_responses


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
        @dataclass
        class Expected:
            account_id: str
            name: str
            credential: Credential

        @pytest.fixture
        async def auth_setup():
            expected = Expected(
                account_id="123456789012",
                name="Test",
                credential=Credential(
                    env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                    expiration="2026-06-01T11:12:44+00:00",
                ),
            )
            mcp = FastMCP("test")
            mock_credentials_manager = MockCredentialsManager()
            accounts = Accounts(f"""{{
                login: {{ type: "sso" }},
                accounts: {{ "{expected.account_id}": {{ name: "{expected.name}", read_profile: "test-read", write_profile: "test-write" }} }},
            }}""")
            auth_tool = AwsAuthTool(Role.READ_ONLY, accounts, mock_credentials_manager)
            await register(mcp, _accounts=accounts, _auth_read=auth_tool)
            async with Client(transport=mcp) as c:
                yield expected, c, auth_tool, mock_credentials_manager

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
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(True)
            mock_credentials_manager.fetch_credentials = return_responses(expected.credential)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {expected.account_id: {"name": expected.name, "expires_at": expected.credential.expiration}}
            )

        async def it_logs_in_when_not_validated(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(False, True)
            mock_credentials_manager.login = return_responses(None)
            mock_credentials_manager.fetch_credentials = return_responses(expected.credential)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {expected.account_id: {"name": expected.name, "expires_at": expected.credential.expiration}}
            )

        async def it_raises_when_post_login_validation_fails(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(False, False)
            mock_credentials_manager.login = return_responses(None)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(f"Login succeeded but credentials are still invalid for {expected.account_id}")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_raises_when_account_is_unknown(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup

            result = await client.call_tool("aws_auth_read", {"account_id": "000000000000"}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("Unknown account: 000000000000")

        async def it_raises_when_login_raises_tool_error(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(False)
            mock_credentials_manager.login = return_responses(ToolError("user cancelled"))

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("user cancelled")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_skips_login_when_credentials_are_still_valid(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(True, True)
            mock_credentials_manager.fetch_credentials = return_responses(expected.credential, expected.credential)

            first = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(first.is_error).is_false()

            second = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()

        async def it_re_logs_in_when_credentials_expire(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(True, False, True)
            mock_credentials_manager.login = return_responses(None)
            mock_credentials_manager.fetch_credentials = return_responses(expected.credential, expected.credential)

            first = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(first.is_error).is_false()

            second = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()

        async def it_raises_when_validate_raises_an_error(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(ToolError("wrong account"))

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_raises_when_post_login_validate_raises_an_error(auth_setup) -> None:
            expected, client, auth_tool, mock_credentials_manager = auth_setup
            mock_credentials_manager.validate = return_responses(False, ToolError("wrong account"))
            mock_credentials_manager.login = return_responses(None)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()
