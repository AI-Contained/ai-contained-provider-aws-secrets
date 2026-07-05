import dataclasses
import json
from collections.abc import AsyncGenerator
from dataclasses import dataclass

import httpx
import pytest
from assertpy import assert_that

from ai_contained.core.mcp.harness import ExecResponse
from ai_contained.provider import aws_secrets
from ai_contained.provider.aws_secrets.credentials_manager import Credential
from ai_contained.provider.aws_secrets.testing import LocalHarness
from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection


def describe_AwsSecretRoute():
    ACCOUNT_ID = "123456789012"

    @dataclass
    class Expected:
        account_id: str
        name: str
        credential: Credential

    def _export_stdout(credential: Credential) -> str:
        """What `aws configure export-credentials --format env` prints for this credential."""
        lines = [f"export {key}={value}" for key, value in credential.env.items()]
        if credential.expiration is not None:
            lines.append(f"export AWS_CREDENTIAL_EXPIRATION={credential.expiration}")
        return "\n".join(lines) + "\n"

    @pytest.fixture
    async def secret_setup() -> AsyncGenerator:
        expected_name = "Test"
        expected = Expected(
            account_id=ACCOUNT_ID,
            name=expected_name,
            credential=Credential(
                name=expected_name,
                env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                expiration="2026-06-01T11:12:44+00:00",
            ),
        )
        accounts_json = f"""{{
            login: {{ type: "sso" }},
            accounts: {{ "{expected.account_id}": {{
                name: "{expected.name}", read_profile: "test-read", write_profile: "test-write"
            }} }},
        }}"""

        async with LocalHarness(env={"TRUST_CLIENTS": "127.0.0.1"}) as h:
            await h.install(trust_server.provide)
            path = h.write("accounts.json5", accounts_json)
            await h.install(aws_secrets.provide, env={"AWS_ACCOUNTS_CONFIG_PATH": path})

            # The real CredentialsManager shells out to aws — answer via shims.
            h.exec("aws").on("sts", "get-caller-identity").returns(
                ExecResponse(stdout=json.dumps({"Account": expected.account_id}))
            )
            h.exec("aws").on("configure", "export-credentials").returns(
                ExecResponse(stdout=_export_stdout(expected.credential))
            )

            # trust_client
            async with h.raw_client() as http:
                conn = TrustConnection(http)
                await conn.register()
                yield expected, TrustClient(_connection=conn, _path="/aws/secret"), h

    async def it_dispenses_credentials_to_authorized_callers(secret_setup) -> None:
        expected, client, harness = secret_setup
        await harness.aws_auth_read(expected.account_id)

        result = await client.post({"account_id": expected.account_id, "role": "ReadOnly"})

        assert_that(result).is_equal_to({expected.account_id: dataclasses.asdict(expected.credential)})

    async def it_dispenses_credentials_without_expiration(secret_setup) -> None:
        expected, client, harness = secret_setup
        credential = Credential(name=expected.name, env=expected.credential.env, expiration=None)
        await harness.aws_auth_read(expected.account_id)
        harness.exec("aws").on("configure", "export-credentials").returns(
            ExecResponse(stdout=_export_stdout(credential))
        )

        result = await client.post({"account_id": expected.account_id, "role": "ReadOnly"})

        assert_that(result).is_equal_to({expected.account_id: dataclasses.asdict(credential)})

    async def it_blocks_unauthorized_callers(secret_setup) -> None:
        expected, client, _ = secret_setup

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post({"account_id": expected.account_id, "role": "ReadOnly"})

        assert_that(exc_info.value.response.status_code).is_equal_to(403)
        assert_that(exc_info.value.response.json()).is_equal_to(
            {
                "code": "NOT_AUTHORIZED",
                "detail": f"Call aws_auth_read('{expected.account_id}') to authenticate, then retry",
            }
        )

    async def it_rejects_unknown_accounts(secret_setup) -> None:
        _, client, _ = secret_setup

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post({"account_id": "000000000000", "role": "ReadOnly"})

        assert_that(exc_info.value.response.status_code).is_equal_to(404)
        assert_that(exc_info.value.response.json()).is_equal_to(
            {
                "code": "UNKNOWN_ACCOUNT",
                "detail": "Account '000000000000' is not configured",
            }
        )

    async def it_signals_session_expired_when_credentials_are_unavailable(secret_setup) -> None:
        expected, client, harness = secret_setup
        await harness.aws_auth_read(expected.account_id)
        harness.exec("aws").on("configure", "export-credentials").returns(ExecResponse(exit_code=1))

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post({"account_id": expected.account_id, "role": "ReadOnly"})

        assert_that(exc_info.value.response.status_code).is_equal_to(401)
        assert_that(exc_info.value.response.json()).is_equal_to(
            {
                "code": "SESSION_EXPIRED",
                "detail": f"Call aws_auth_read('{expected.account_id}') to re-authenticate, then retry",
            }
        )

    @pytest.mark.parametrize(
        "payload,detail",
        [
            pytest.param({"role": "ReadOnly"}, "account_id is required", id="missing account_id"),
            pytest.param({"account_id": ACCOUNT_ID}, "role must be 'ReadOnly' or 'ReadWrite'", id="missing role"),
            pytest.param(
                {"account_id": ACCOUNT_ID, "role": "SuperAdmin"},
                "role must be 'ReadOnly' or 'ReadWrite'",
                id="invalid role",
            ),
        ],
    )
    async def it_rejects_invalid_requests(secret_setup, payload, detail) -> None:
        _, client, _ = secret_setup

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post(payload)

        assert_that(exc_info.value.response.status_code).is_equal_to(400)
        assert_that(exc_info.value.response.json()).is_equal_to({"code": "INVALID_REQUEST", "detail": detail})

    async def it_dispenses_write_credentials_for_read_write_role(secret_setup) -> None:
        expected, client, harness = secret_setup
        credential = Credential(name=expected.name, env=expected.credential.env, expiration=None)
        await harness.aws_auth_write(expected.account_id)
        harness.exec("aws").on("configure", "export-credentials").returns(
            ExecResponse(stdout=_export_stdout(credential))
        )

        result = await client.post({"account_id": expected.account_id, "role": "ReadWrite"})

        assert_that(result).is_equal_to({expected.account_id: dataclasses.asdict(credential)})
