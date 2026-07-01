import json
from dataclasses import dataclass

import pytest
from assertpy import assert_that
from conftest import MockCredentialsManager, return_responses
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.exceptions import ToolError

from ai_contained.core.mcp.testing import Elicitor
from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.credentials_manager import Credential
from ai_contained.provider.aws_secrets.types import Role


def describe_AwsAuthTool():
    def describe_is_authorized():
        ACCOUNT_ID = "123456789012"

        @pytest.fixture
        def auth_tool():
            return AwsAuthTool(Role.READ_ONLY, Accounts('{ login: { type: "sso" }, accounts: {} }'))

        def it_returns_false_by_default(auth_tool: AwsAuthTool) -> None:
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        def it_returns_false_after_revoke(auth_tool: AwsAuthTool) -> None:
            auth_tool.authorize(ACCOUNT_ID)
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

            auth_tool.revoke(ACCOUNT_ID)
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        def it_returns_false_after_revoke_all(auth_tool: AwsAuthTool) -> None:
            auth_tool.authorize(ACCOUNT_ID)
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

            auth_tool.revoke_all()
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_false()

        def it_is_idempotent_when_authorizing_twice(auth_tool: AwsAuthTool) -> None:
            auth_tool.authorize(ACCOUNT_ID)
            auth_tool.authorize(ACCOUNT_ID)
            assert_that(auth_tool.is_authorized(ACCOUNT_ID)).is_true()

    def describe_revoke():
        ACCOUNT_A = "123456789012"
        ACCOUNT_B = "456789012345"

        @pytest.fixture
        def auth_tool():
            return AwsAuthTool(Role.READ_ONLY, Accounts('{ login: { type: "sso" }, accounts: {} }'))

        def it_does_not_raise_when_revoking_unknown_account(auth_tool: AwsAuthTool) -> None:
            auth_tool.revoke(ACCOUNT_A)
            assert_that(auth_tool.is_authorized(ACCOUNT_A)).is_false()

        def it_only_revokes_target_account(auth_tool: AwsAuthTool) -> None:
            auth_tool.authorize(ACCOUNT_A)
            auth_tool.authorize(ACCOUNT_B)
            assert_that(auth_tool.is_authorized(ACCOUNT_A)).is_true()
            assert_that(auth_tool.is_authorized(ACCOUNT_B)).is_true()

            auth_tool.revoke(ACCOUNT_A)
            assert_that(auth_tool.is_authorized(ACCOUNT_A)).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_B)).is_true()

        def it_revoke_all_clears_all_accounts(auth_tool: AwsAuthTool) -> None:
            auth_tool.authorize(ACCOUNT_A)
            auth_tool.authorize(ACCOUNT_B)
            assert_that(auth_tool.is_authorized(ACCOUNT_A)).is_true()
            assert_that(auth_tool.is_authorized(ACCOUNT_B)).is_true()

            auth_tool.revoke_all()
            assert_that(auth_tool.is_authorized(ACCOUNT_A)).is_false()
            assert_that(auth_tool.is_authorized(ACCOUNT_B)).is_false()

    def describe_register():
        async def it_registers_nothing_when_no_config_path_is_set() -> None:
            mcp = FastMCP("test")

            await register(mcp)

            assert_that(await mcp.list_tools()).is_empty()

        async def it_exposes_read_and_write_tools() -> None:
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

    def describe_authenticate():
        @dataclass
        class Expected:
            account_id: str
            name: str
            credential: Credential

            def auth_prompt(self) -> str:
                return f"I'd like ReadOnly AWS Access to {self.name}({self.account_id}). (using tool: aws_auth_read)"

        @dataclass
        class Mock:
            credentials_manager: MockCredentialsManager
            elicitor: Elicitor

        @pytest.fixture
        async def auth_setup(monkeypatch: pytest.MonkeyPatch):
            monkeypatch.setenv("COLOR", "off")
            expected_name = "Test"
            expected = Expected(
                account_id="123456789012",
                name=expected_name,
                credential=Credential(
                    name=expected_name,
                    env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                    expiration="2026-06-01T11:12:44+00:00",
                ),
            )
            mock = Mock(credentials_manager=MockCredentialsManager(), elicitor=Elicitor())
            accounts = Accounts(f"""{{
                login: {{ type: "sso" }},
                accounts: {{ "{expected.account_id}": {{
                    name: "{expected.name}", read_profile: "test-read", write_profile: "test-write"
                }} }},
            }}""")
            auth_tool = AwsAuthTool(Role.READ_ONLY, accounts, mock.credentials_manager)
            mcp = FastMCP("test")
            await register(mcp, _accounts=accounts, _auth_read=auth_tool)
            async with Client(transport=mcp, elicitation_handler=mock.elicitor) as c:
                yield expected, c, auth_tool, mock
            assert not mock.elicitor._queue, f"{len(mock.elicitor._queue)} elicitation step(s) were never triggered"

        async def it_authorizes_when_already_validated(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(True)
            mock.credentials_manager.fetch_credentials = return_responses(expected.credential)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {expected.account_id: {"name": expected.name, "expires_at": expected.credential.expiration}}
            )

        async def it_logs_in_when_not_validated(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(False, True)
            mock.credentials_manager.login = return_responses(None)
            mock.credentials_manager.fetch_credentials = return_responses(expected.credential)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()
            assert_that(json.loads(result.content[0].text)).is_equal_to(
                {expected.account_id: {"name": expected.name, "expires_at": expected.credential.expiration}}
            )

        async def it_rejects_account_when_credentials_remain_invalid_after_login(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(False, False)
            mock.credentials_manager.login = return_responses(None)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(
                f"Login succeeded but credentials are still invalid for {expected.account_id}"
            )
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_raises_when_user_declines_access(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.decline(expect_message=expected.auth_prompt())

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to(f"Access to aws_auth_read({expected.name}) was declined")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_rejects_unknown_accounts(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup

            result = await client.call_tool("aws_auth_read", {"account_id": "000000000000"}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("Unknown account: 000000000000")

        async def it_propagates_login_errors_to_the_caller(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(False)
            mock.credentials_manager.login = return_responses(ToolError("user cancelled"))

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("user cancelled")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_skips_login_when_credentials_are_still_valid(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(True, True)
            mock.credentials_manager.fetch_credentials = return_responses(expected.credential, expected.credential)

            first = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(first.is_error).is_false()

            second = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()

        async def it_re_logs_in_when_credentials_expire(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(True, False, True)
            mock.credentials_manager.login = return_responses(None)
            mock.credentials_manager.fetch_credentials = return_responses(expected.credential, expected.credential)

            first = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(first.is_error).is_false()

            second = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)
            assert_that(second.is_error).is_false()
            assert_that(auth_tool.is_authorized(expected.account_id)).is_true()

        async def it_propagates_validation_errors_to_the_caller(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(ToolError("wrong account"))

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()

        async def it_propagates_post_login_validation_errors_to_the_caller(auth_setup) -> None:
            expected, client, auth_tool, mock = auth_setup
            mock.elicitor.accept(expect_message=expected.auth_prompt())
            mock.credentials_manager.validate = return_responses(False, ToolError("wrong account"))
            mock.credentials_manager.login = return_responses(None)

            result = await client.call_tool("aws_auth_read", {"account_id": expected.account_id}, raise_on_error=False)

            assert_that(result.is_error).is_true()
            assert_that(result.content[0].text).is_equal_to("wrong account")
            assert_that(auth_tool.is_authorized(expected.account_id)).is_false()
