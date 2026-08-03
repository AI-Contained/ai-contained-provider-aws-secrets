import os
from pathlib import Path

import pytest
from assertpy import assert_that
from conftest import with_accept_fallback
from fastmcp import Context
from fastmcp.exceptions import ToolError

from ai_contained.core.mcp.harness import Harness
from ai_contained.core.mcp.testing import Elicitor
from ai_contained.provider.aws_secrets.accounts import Account, AccountLogin
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
    def describe_aws_env():
        async def uses_AWS_HOME_when_set() -> None:
            expected = "/secrets/aws-secrets"
            manager = CredentialsManager(
                {"AWS_HOME": expected, "AWS_ACCOUNTS_CONFIG_PATH": "/elsewhere/accounts.json5"}
            )
            result = manager._aws_env()
            assert_that(result["HOME"]).is_equal_to(expected)

        async def falls_back_to_dirname_of_AWS_ACCOUNTS_CONFIG_PATH() -> None:
            expected = "/secrets/aws-secrets"
            manager = CredentialsManager({"AWS_ACCOUNTS_CONFIG_PATH": f"{expected}/accounts.json5"})
            result = manager._aws_env()
            assert_that(result["HOME"]).is_equal_to(expected)

        async def leaves_HOME_alone_when_neither_is_set() -> None:
            expected = "/root"
            result = CredentialsManager({"HOME": expected})._aws_env()
            assert_that(result["HOME"]).is_equal_to(expected)

        async def applies_kwargs_as_overrides() -> None:
            expected = "test-read"
            result = CredentialsManager({})._aws_env(AWS_PROFILE=expected)
            assert_that(result["AWS_PROFILE"]).is_equal_to(expected)

    def describe_validate():
        mock_sts = str(Path(__file__).parent / "bin" / "mock_aws_sts.sh")

        async def returns_false_when_command_exits_nonzero() -> None:
            expected = make_account(read_profile="mock-profile", check_command=mock_sts)
            result = await CredentialsManager({"MOCK_STS_EXIT_CODE": "1"}).validate(Role.READ_ONLY, expected)
            assert_that(result).is_false()

        async def returns_true_when_account_id_matches() -> None:
            expected = make_account(account_id="123456789012", read_profile="mock-profile", check_command=mock_sts)
            manager = CredentialsManager({"MOCK_STS_ACCOUNT_ID": expected.account_id})
            result = await manager.validate(Role.READ_ONLY, expected)
            assert_that(result).is_true()

        async def raises_when_account_id_does_not_match() -> None:
            expected = make_account(account_id="123456789012", read_profile="mock-profile", check_command=mock_sts)
            manager = CredentialsManager({"MOCK_STS_ACCOUNT_ID": "999999999999"})
            with pytest.raises(ToolError) as exc_info:
                await manager.validate(Role.READ_ONLY, expected)
            assert_that(str(exc_info.value)).contains(f"expected '{expected.account_id}'")

        async def raises_when_response_is_not_valid_json() -> None:
            account = make_account(
                read_profile="mock-profile",
                check_command="/bin/sh -c 'echo not-json; exit 0'",
            )
            with pytest.raises(ToolError) as exc_info:
                await CredentialsManager({}).validate(Role.READ_ONLY, account)
            assert_that(str(exc_info.value)).contains("invalid response")

        async def raises_when_response_is_missing_account_key() -> None:
            account = make_account(
                read_profile="mock-profile",
                check_command='/bin/sh -c \'echo {"UserId": "foo"}; exit 0\'',
            )
            with pytest.raises(ToolError) as exc_info:
                await CredentialsManager({}).validate(Role.READ_ONLY, account)
            assert_that(str(exc_info.value)).contains("invalid response")

    def describe_fetch_credentials():
        mock_export = str(Path(__file__).parent / "bin" / "mock_aws_export.sh")

        async def returns_credential_with_env_and_expiration() -> None:
            expected_env = {
                "AWS_ACCESS_KEY_ID": "AKID123",
                "AWS_SECRET_ACCESS_KEY": "SECRET123",
                "AWS_SESSION_TOKEN": "TOKEN123",
            }
            expected_expiration = "2026-06-01T11:12:44+00:00"
            manager = CredentialsManager(
                {
                    "MOCK_EXPORT_ACCESS_KEY_ID": expected_env["AWS_ACCESS_KEY_ID"],
                    "MOCK_EXPORT_SECRET_ACCESS_KEY": expected_env["AWS_SECRET_ACCESS_KEY"],
                    "MOCK_EXPORT_SESSION_TOKEN": expected_env["AWS_SESSION_TOKEN"],
                    "MOCK_EXPORT_EXPIRATION": expected_expiration,
                }
            )
            account = make_account(read_profile="mock-profile", fetch_command=mock_export)
            result = await manager.fetch_credentials(Role.READ_ONLY, account)
            assert_that(result.env).is_equal_to(expected_env)
            assert_that(result.expiration).is_equal_to(expected_expiration)

        async def returns_none_expiration_when_not_present() -> None:
            manager = CredentialsManager({"MOCK_EXPORT_INCLUDE_EXPIRATION": "0"})
            account = make_account(read_profile="mock-profile", fetch_command=mock_export)
            result = await manager.fetch_credentials(Role.READ_ONLY, account)
            assert_that(result.expiration).is_none()

        @pytest.mark.parametrize(
            "role, expected_tool",
            [
                pytest.param(Role.READ_ONLY, "aws_auth_read", id="read_only"),
                pytest.param(Role.READ_WRITE, "aws_auth_write", id="read_write"),
            ],
        )
        async def raises_with_recovery_hint_when_command_exits_nonzero(role: Role, expected_tool: str) -> None:
            manager = CredentialsManager({"MOCK_EXPORT_EXIT_CODE": "1"})
            account = make_account(read_profile="mock-profile", write_profile="mock-profile", fetch_command=mock_export)
            expected = f"Credentials unavailable for {account.account_id}: call {expected_tool} to re-authenticate"
            with pytest.raises(ToolError) as exc_info:
                await manager.fetch_credentials(role, account)
            assert_that(str(exc_info.value)).is_equal_to(expected)

    def describe_login():
        def describe_preauth():
            async def raises_immediately() -> None:
                account = make_account(read_profile="some-profile", login_type=LoginType.PREAUTH)
                with pytest.raises(ToolError) as exc_info:
                    await CredentialsManager({}).login(None, Role.READ_ONLY, account)  # type: ignore[arg-type]
                assert_that(str(exc_info.value)).is_equal_to("credentials invalid — fix externally and retry")

        def describe_sso():

            LOOP_ELICITATION_MESSAGE = (
                "AWS SSO Login is still processing the authorization request.\n\n"
                "Click Allow to check again, or Decline to cancel."
            )

            LOGIN_HINT = "After completing login in your browser, click Accept to continue."

            def _decline_asserting_url(msg, rtype, params, ctx):
                lines = msg.splitlines()
                assert_that(lines[-3]).starts_with("https://")
                assert_that(lines[-2]).is_empty()
                assert_that(lines[-1]).is_equal_to(LOGIN_HINT)
                return ("decline", None)

            def _accept_asserting_url(msg, rtype, params, ctx):
                lines = msg.splitlines()
                assert_that(lines[-3]).starts_with("https://")
                assert_that(lines[-2]).is_empty()
                assert_that(lines[-1]).is_equal_to(LOGIN_HINT)
                return ("accept", None)

            # Success cases only assert is_error=False — the return value is "ok" from
            # test_login, not from login() itself, so it's not worth asserting here.

            @pytest.fixture
            def mock_account() -> Account:
                return make_account(
                    read_profile="mock-profile",
                    login_type=LoginType.SSO,
                    command=str(Path(__file__).parent / "bin" / "mock_aws_sso_login.sh"),
                )

            def _login_harness(account: Account, env: dict[str, str]) -> Harness:
                """A harness whose test_login tool drives CredentialsManager.login() for the account."""
                h = Harness(env=env)
                credentials_manager = CredentialsManager(h.env)

                @h.mcp.tool()
                async def test_login(ctx: Context) -> str:
                    await credentials_manager.login(ctx, Role.READ_ONLY, account)
                    return "ok"

                return h

            async def raises_when_sso_command_does_not_exist() -> None:
                account = make_account(
                    read_profile="mock-profile",
                    login_type=LoginType.SSO,
                    command="non-existent-command",
                )
                async with _login_harness(account, {}) as h:
                    async with h.client() as c:
                        result = await c.tool("test_login")()

                assert_that(result.is_error).is_true()
                error = result.json()
                assert_that(error["exit_status"]).is_equal_to("127")
                assert_that(error["stdout"]).is_equal_to("")
                assert_that(error["stderr"]).contains("non-existent-command")

            async def raises_when_sso_command_exits_before_emitting_urls() -> None:
                expected = {"exit_status": "2", "stdout": "out_line\n", "stderr": "err_line\n"}
                account = make_account(
                    read_profile="mock-profile",
                    login_type=LoginType.SSO,
                    command='/bin/sh -c \'echo -n "{stdout}"; echo -n "{stderr}" >&2; exit {exit_code}\''.format(
                        **expected, exit_code=int(expected["exit_status"])
                    ),
                )
                async with _login_harness(account, {}) as h:
                    async with h.client() as c:
                        result = await c.tool("test_login")()

                assert_that(result.is_error).is_true()
                assert_that(result.json()).is_equal_to(expected)

            async def raises_when_user_declines_initial_elicitation(mock_account: Account) -> None:
                async with _login_harness(mock_account, {}) as h:
                    h.elicit.on_elicit(_decline_asserting_url)
                    async with h.client() as c:
                        result = await c.tool("test_login")()
                assert_that(result.is_error).is_true()

            async def raises_when_sso_command_exits_nonzero(
                mock_account: Account, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                monkeypatch.setattr(Elicitor, "__call__", with_accept_fallback)
                async with _login_harness(mock_account, {"MOCK_SSO_EXIT_CODE": "1"}) as h:
                    h.elicit.on_elicit(_accept_asserting_url)
                    async with h.client() as c:
                        result = await c.tool("test_login")()
                assert_that(result.is_error).is_true()

            async def succeeds_when_user_accepts_and_command_exits_zero(
                mock_account: Account, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                monkeypatch.setattr(Elicitor, "__call__", with_accept_fallback)
                async with _login_harness(mock_account, {}) as h:
                    h.elicit.on_elicit(_accept_asserting_url)
                    async with h.client() as c:
                        result = await c.tool("test_login")()
                assert_that(result.is_error).is_false()
                # return value not asserted — it's "ok" from test_login, not from login()

            async def raises_when_user_declines_while_waiting_for_aws(mock_account: Account, tmp_path: Path) -> None:
                fifo = tmp_path / "sso.fifo"
                os.mkfifo(fifo)
                async with _login_harness(mock_account, {"MOCK_SSO_FIFO": str(fifo)}) as h:
                    h.elicit.on_elicit(_accept_asserting_url)
                    h.elicit.decline(expect_message=LOOP_ELICITATION_MESSAGE)
                    async with h.client() as c:
                        result = await c.tool("test_login")()
                assert_that(result.is_error).is_true()

            @pytest.mark.skip(reason="reliably fails on GHA with McpError: [Errno 32] Broken pipe")
            async def succeeds_after_waiting_for_aws_to_confirm(
                mock_account: Account, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
            ) -> None:
                monkeypatch.setattr(Elicitor, "__call__", with_accept_fallback)
                fifo = tmp_path / "sso.fifo"
                os.mkfifo(fifo)

                def accept_and_unblock(msg, rtype, params, ctx):
                    assert_that(msg).is_equal_to(LOOP_ELICITATION_MESSAGE)
                    # Signal to the mock SSO script that authorization is complete.
                    with open(str(fifo), "w") as f:
                        f.write("done\n")
                    return ("accept", None)

                async with _login_harness(mock_account, {"MOCK_SSO_FIFO": str(fifo)}) as h:
                    h.elicit.on_elicit(_accept_asserting_url)
                    h.elicit.on_elicit(accept_and_unblock)
                    async with h.client() as c:
                        result = await c.tool("test_login")()
                assert_that(result.is_error).is_false()
