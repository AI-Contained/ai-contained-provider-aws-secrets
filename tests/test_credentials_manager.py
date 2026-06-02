import os
from collections.abc import AsyncGenerator, Generator
from pathlib import Path

import pytest
from assertpy import assert_that
from fastmcp import Context, FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import FastMCPTransport

from mcp.types import TextContent

from ai_contained.core.mcp.testing import Elicitor, WrapCallToolResult
from ai_contained.provider.aws_secrets.accounts import Account, AccountLogin
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets.credentials_manager import CredentialsManager
from ai_contained.provider.aws_secrets.types import LoginType, Role


def make_account(
    *,
    account_id: str = "123456789012",
    read_profile: str | None = None,
    write_profile: str | None = None,
    login_type: LoginType = LoginType.PREAUTH,
    command: str | None = None,
    check_command: str | None = None,
    fetch_command: str | None = None,
) -> Account:
    return Account(
        account_id=account_id,
        name="Test",
        trust_groups=[],
        read_profile=read_profile,
        write_profile=write_profile,
        login=AccountLogin(type=login_type, command=command, check_command=check_command, fetch_command=fetch_command),
    )


def describe_CredentialsManager():
    def describe_validate():
        mock_sts = str(Path(__file__).parent / "bin" / "mock_aws_sts.sh")

        async def returns_false_when_command_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setenv("MOCK_STS_EXIT_CODE", "1")
            expected = make_account(read_profile="mock-profile", check_command=mock_sts)
            result = await CredentialsManager().validate(Role.READ_ONLY, expected)
            assert_that(result).is_false()

        async def returns_true_when_account_id_matches(monkeypatch: pytest.MonkeyPatch) -> None:
            expected = make_account(account_id="123456789012", read_profile="mock-profile", check_command=mock_sts)
            monkeypatch.setenv("MOCK_STS_ACCOUNT_ID", expected.account_id)
            result = await CredentialsManager().validate(Role.READ_ONLY, expected)
            assert_that(result).is_true()

        async def raises_when_account_id_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setenv("MOCK_STS_ACCOUNT_ID", "999999999999")
            expected = make_account(account_id="123456789012", read_profile="mock-profile", check_command=mock_sts)
            with pytest.raises(ToolError) as exc_info:
                await CredentialsManager().validate(Role.READ_ONLY, expected)
            assert_that(str(exc_info.value)).contains(f"expected '{expected.account_id}'")

        async def raises_when_response_is_not_valid_json() -> None:
            account = make_account(
                read_profile="mock-profile",
                check_command="/bin/sh -c 'echo not-json; exit 0'",
            )
            with pytest.raises(ToolError) as exc_info:
                await CredentialsManager().validate(Role.READ_ONLY, account)
            assert_that(str(exc_info.value)).contains("invalid response")

        async def raises_when_response_is_missing_account_key() -> None:
            account = make_account(
                read_profile="mock-profile",
                check_command="/bin/sh -c 'echo {\"UserId\": \"foo\"}; exit 0'",
            )
            with pytest.raises(ToolError) as exc_info:
                await CredentialsManager().validate(Role.READ_ONLY, account)
            assert_that(str(exc_info.value)).contains("invalid response")



    def describe_fetch_credentials():
        mock_export = str(Path(__file__).parent / "bin" / "mock_aws_export.sh")

        async def returns_credential_with_env_and_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
            expected_env = {
                "AWS_ACCESS_KEY_ID": "AKID123",
                "AWS_SECRET_ACCESS_KEY": "SECRET123",
                "AWS_SESSION_TOKEN": "TOKEN123"
            }
            expected_expiration = "2026-06-01T11:12:44+00:00"
            monkeypatch.setenv("MOCK_EXPORT_ACCESS_KEY_ID", expected_env["AWS_ACCESS_KEY_ID"])
            monkeypatch.setenv("MOCK_EXPORT_SECRET_ACCESS_KEY", expected_env["AWS_SECRET_ACCESS_KEY"])
            monkeypatch.setenv("MOCK_EXPORT_SESSION_TOKEN", expected_env["AWS_SESSION_TOKEN"])
            monkeypatch.setenv("MOCK_EXPORT_EXPIRATION", expected_expiration)
            account = make_account(read_profile="mock-profile", fetch_command=mock_export)
            result = await CredentialsManager().fetch_credentials(Role.READ_ONLY, account)
            assert_that(result.env).is_equal_to(expected_env)
            assert_that(result.expiration).is_equal_to(expected_expiration)

        async def returns_none_expiration_when_not_present(monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setenv("MOCK_EXPORT_INCLUDE_EXPIRATION", "0")
            account = make_account(read_profile="mock-profile", fetch_command=mock_export)
            result = await CredentialsManager().fetch_credentials(Role.READ_ONLY, account)
            assert_that(result.expiration).is_none()

        async def raises_when_command_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setenv("MOCK_EXPORT_EXIT_CODE", "1")
            account = make_account(read_profile="mock-profile", fetch_command=mock_export)
            with pytest.raises(ToolError):
                await CredentialsManager().fetch_credentials(Role.READ_ONLY, account)

    def describe_login():
        @pytest.fixture
        def elicitor() -> Generator[Elicitor, None, None]:
            e = Elicitor()
            yield e
            assert not e._queue, f"{len(e._queue)} elicitation step(s) were never triggered"

        def describe_preauth():
            async def raises_immediately() -> None:
                account = make_account(read_profile="some-profile", login_type=LoginType.PREAUTH)
                with pytest.raises(ToolError) as exc_info:
                    await CredentialsManager().login(None, Role.READ_ONLY, account)  # type: ignore[arg-type]
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

            # Success cases only assert is_error=False — the return value is "ok" from
            # fake_login, not from login() itself, so it's not worth asserting here.

            @pytest.fixture
            def mock_account() -> Account:
                return make_account(
                    read_profile="mock-profile",
                    login_type=LoginType.SSO,
                    command=str(Path(__file__).parent / "bin" / "mock_aws_sso_login.sh"),
                )

            @pytest.fixture
            async def client(elicitor: Elicitor, mock_account: Account) -> AsyncGenerator[Client[FastMCPTransport], None]:
                server = FastMCP("test")
                credentials_manager = CredentialsManager()

                @server.tool()
                async def fake_login(ctx: Context) -> str:
                    await credentials_manager.login(ctx, Role.READ_ONLY, mock_account)
                    return "ok"

                async with Client(transport=server, elicitation_handler=elicitor) as c:
                    yield c

            async def raises_when_sso_command_does_not_exist(elicitor: Elicitor) -> None:
                account = make_account(
                    read_profile="mock-profile",
                    login_type=LoginType.SSO,
                    command="non-existent-command",
                )
                server = FastMCP("test")

                @server.tool()
                async def fake_login(ctx: Context) -> str:
                    await CredentialsManager().login(ctx, Role.READ_ONLY, account)
                    return "ok"

                async with Client(transport=server, elicitation_handler=elicitor) as c:
                    result = WrapCallToolResult(**vars(await c.call_tool("fake_login", {}, raise_on_error=False)))

                assert_that(result.is_error).is_true()
                error = result.json()
                assert_that(error["exit_status"]).is_equal_to("127")
                assert_that(error["stdout"]).is_equal_to("")
                assert_that(error["stderr"]).contains("non-existent-command")

            async def raises_when_sso_command_exits_before_emitting_urls(elicitor: Elicitor) -> None:
                expected = {"exit_status": "2", "stdout": "out_line\n", "stderr": "err_line\n"}
                account = make_account(
                    read_profile="mock-profile",
                    login_type=LoginType.SSO,
                    command="/bin/sh -c 'echo -n \"{stdout}\"; echo -n \"{stderr}\" >&2; exit {exit_code}'".format(
                        **expected, exit_code=int(expected["exit_status"])
                    ),
                )
                server = FastMCP("test")

                @server.tool()
                async def fake_login(ctx: Context) -> str:
                    await CredentialsManager().login(ctx, Role.READ_ONLY, account)
                    return "ok"

                async with Client(transport=server, elicitation_handler=elicitor) as c:
                    result = WrapCallToolResult(**vars(await c.call_tool("fake_login", {}, raise_on_error=False)))

                assert_that(result.is_error).is_true()
                assert_that(result.json()).is_equal_to(expected)

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
                # return value not asserted — it's "ok" from fake_login, not from login()

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
                    assert_that(msg).is_equal_to(LOOP_ELICITATION_MESSAGE)
                    # We signal to our MOCK SSO app that we're finished
                    with open(str(fifo), "w") as f:
                        f.write("done\n")
                    return ("accept", None)

                elicitor.on_elicit(accept_and_unblock)
                result = await client.call_tool("fake_login", {}, raise_on_error=False)
                assert_that(result.is_error).is_false()
