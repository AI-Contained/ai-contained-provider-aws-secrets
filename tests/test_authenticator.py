import os
from collections.abc import AsyncGenerator, Generator
from pathlib import Path

import pytest
from assertpy import assert_that
from fastmcp import Context, FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import FastMCPTransport

from mcp.types import TextContent

from ai_contained.core.mcp.testing import Elicitor
from ai_contained.provider.aws_secrets.accounts import Account, AccountLogin
from ai_contained.provider.aws_secrets.authenticator import Authenticator, AuthenticationError
from ai_contained.provider.aws_secrets.types import LoginType, Role


def make_account(
    *,
    account_id: str = "123456789012",
    read_profile: str | None = None,
    write_profile: str | None = None,
    login_type: LoginType = LoginType.PREAUTH,
    command: str | None = None,
) -> Account:
    return Account(
        account_id=account_id,
        name="Test",
        trust_groups=[],
        read_profile=read_profile,
        write_profile=write_profile,
        login=AccountLogin(type=login_type, command=command),
    )


def describe_Authenticator():
    @pytest.fixture
    def aws_account_id() -> str:
        account_id = os.environ.get("TEST_AWS_ACCOUNT_ID")
        if not account_id:
            pytest.skip("TEST_AWS_ACCOUNT_ID not set")
        return account_id

    @pytest.fixture
    def aws_profile() -> str:
        profile = os.environ.get("TEST_AWS_PROFILE")
        if not profile:
            pytest.skip("TEST_AWS_PROFILE not set")
        return profile

    def describe_validate():
        async def returns_false_when_credentials_are_absent_or_expired() -> None:
            account = make_account(read_profile="nonexistent-profile-xyz")
            result = await Authenticator().validate(Role.READ_ONLY, account)
            assert_that(result).is_false()

        async def returns_true_when_credentials_are_valid(aws_account_id: str, aws_profile: str) -> None:
            account = make_account(account_id=aws_account_id, read_profile=aws_profile)
            result = await Authenticator().validate(Role.READ_ONLY, account)
            assert_that(result).is_true()

        async def raises_when_credentials_resolve_to_the_wrong_account(aws_profile: str) -> None:
            account = make_account(account_id="000000000000", read_profile=aws_profile)
            with pytest.raises(AuthenticationError) as exc_info:
                await Authenticator().validate(Role.READ_ONLY, account)
            assert_that(str(exc_info.value)).contains("expected '000000000000'")

    def describe_login():
        @pytest.fixture
        def elicitor() -> Generator[Elicitor, None, None]:
            e = Elicitor()
            yield e
            assert not e._queue, f"{len(e._queue)} elicitation step(s) were never triggered"

        def describe_preauth():
            async def raises_immediately() -> None:
                account = make_account(read_profile="some-profile", login_type=LoginType.PREAUTH)
                with pytest.raises(AuthenticationError) as exc_info:
                    await Authenticator().login(None, Role.READ_ONLY, account)  # type: ignore[arg-type]
                assert_that(str(exc_info.value)).is_equal_to("credentials invalid — fix externally and retry")

        def describe_sso():
            LOOP_ELICITATION_MESSAGE = (
                "AWS SSO Login is still processing the authorization request.\n\n"
                "Click Allow to check again, or Decline to cancel."
            )

            def _decline_asserting_url(msg, rtype, params, ctx):
                assert_that(msg).ends_with("\n")
                assert_that(msg.splitlines()[-1]).starts_with("https://")
                return ("decline", None)

            def _accept_asserting_url(msg, rtype, params, ctx):
                assert_that(msg).ends_with("\n")
                assert_that(msg.splitlines()[-1]).starts_with("https://")
                return ("accept", None)

            @pytest.fixture
            def mock_account() -> Account:
                return make_account(
                    login_type=LoginType.SSO,
                    command="tests/bin/mock_aws_sso_login.sh",
                )

            @pytest.fixture
            async def client(elicitor: Elicitor, mock_account: Account) -> AsyncGenerator[Client[FastMCPTransport], None]:
                server = FastMCP("test")
                authenticator = Authenticator()

                @server.tool()
                async def fake_login(ctx: Context) -> str:
                    await authenticator.login(ctx, Role.READ_ONLY, mock_account)
                    return "ok"

                async with Client(transport=server, elicitation_handler=elicitor) as c:
                    yield c

            async def raises_when_user_declines_initial_elicitation(
                client: Client[FastMCPTransport], elicitor: Elicitor
            ) -> None:
                elicitor.on_elicit(_decline_asserting_url)
                result = await client.call_tool("fake_login", {}, raise_on_error=False)
                assert_that(result.is_error).is_true()

            async def raises_when_sso_command_exits_nonzero(
                client: Client[FastMCPTransport], elicitor: Elicitor, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                monkeypatch.setenv("MOCK_SSO_EXIT_CODE", "1")
                elicitor.on_elicit(_accept_asserting_url)
                result = await client.call_tool("fake_login", {}, raise_on_error=False)
                assert_that(result.is_error).is_true()

            async def succeeds_when_user_accepts_and_command_exits_zero(
                client: Client[FastMCPTransport], elicitor: Elicitor
            ) -> None:
                elicitor.on_elicit(_accept_asserting_url)
                result = await client.call_tool("fake_login", {}, raise_on_error=False)
                assert_that(result.is_error).is_false()

            async def raises_when_user_declines_while_waiting_for_aws(
                client: Client[FastMCPTransport],
                elicitor: Elicitor,
                monkeypatch: pytest.MonkeyPatch,
                tmp_path: Path,
            ) -> None:
                fifo = tmp_path / "sso.fifo"
                os.mkfifo(fifo)
                monkeypatch.setenv("MOCK_SSO_FIFO", str(fifo))
                elicitor.on_elicit(_accept_asserting_url)
                elicitor.decline(expect_message=LOOP_ELICITATION_MESSAGE)
                result = await client.call_tool("fake_login", {}, raise_on_error=False)
                assert_that(result.is_error).is_true()

            async def succeeds_after_waiting_for_aws_to_confirm(
                client: Client[FastMCPTransport],
                elicitor: Elicitor,
                monkeypatch: pytest.MonkeyPatch,
                tmp_path: Path,
            ) -> None:
                fifo = tmp_path / "sso.fifo"
                os.mkfifo(fifo)
                monkeypatch.setenv("MOCK_SSO_FIFO", str(fifo))
                elicitor.on_elicit(_accept_asserting_url)

                def accept_and_unblock(msg, rtype, params, ctx):
                    assert msg == LOOP_ELICITATION_MESSAGE
                    with open(str(fifo), "w") as f:
                        f.write("done\n")
                    return ("accept", None)

                elicitor.on_elicit(accept_and_unblock)
                result = await client.call_tool("fake_login", {}, raise_on_error=False)
                assert_that(result.is_error).is_false()
