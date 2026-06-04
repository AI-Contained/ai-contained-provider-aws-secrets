import dataclasses
from collections.abc import AsyncGenerator
from dataclasses import dataclass

import httpx
import pytest
from assertpy import assert_that
from conftest import MockCredentialsManager, return_responses
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.credentials_manager import Credential
from ai_contained.provider.aws_secrets.types import Role
from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection
from ai_contained.trust.server.trust_store import get_trust_store


def describe_AwsSecretRoute():
    ACCOUNT_ID = "123456789012"

    @dataclass
    class Expected:
        account_id: str
        name: str
        credential: Credential

    @pytest.fixture
    async def secret_setup() -> AsyncGenerator:
        expected = Expected(
            account_id=ACCOUNT_ID,
            name="Test",
            credential=Credential(
                env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
                expiration="2026-06-01T11:12:44+00:00",
            ),
        )
        accounts = Accounts(f"""{{
            login: {{ type: "sso" }},
            accounts: {{ "{expected.account_id}": {{
                name: "{expected.name}", read_profile: "test-read", write_profile: "test-write"
            }} }},
        }}""")
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
            yield (
                expected,
                TrustClient(_connection=conn, _path="/aws/secret"),
                auth_read,
                auth_write,
                mock_credentials_manager,
            )

    async def it_dispenses_credentials_to_authorized_callers(secret_setup) -> None:
        expected, client, auth_read, _, mock_credentials_manager = secret_setup
        auth_read.authorize(expected.account_id)
        mock_credentials_manager.fetch_credentials = return_responses(expected.credential)

        result = await client.post({"account_id": expected.account_id, "role": "ReadOnly"})

        assert_that(result).is_equal_to({expected.account_id: dataclasses.asdict(expected.credential)})

    async def it_dispenses_credentials_without_expiration(secret_setup) -> None:
        expected, client, auth_read, _, mock_credentials_manager = secret_setup
        credential = Credential(
            env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
            expiration=None,
        )
        auth_read.authorize(expected.account_id)
        mock_credentials_manager.fetch_credentials = return_responses(credential)

        result = await client.post({"account_id": expected.account_id, "role": "ReadOnly"})

        assert_that(result).is_equal_to({expected.account_id: dataclasses.asdict(credential)})

    async def it_blocks_unauthorized_callers(secret_setup) -> None:
        expected, client, _, _, _ = secret_setup

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
        _, client, _, _, _ = secret_setup

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
        expected, client, auth_read, _, mock_credentials_manager = secret_setup
        auth_read.authorize(expected.account_id)
        mock_credentials_manager.fetch_credentials = return_responses(ToolError("credentials unavailable"))

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
        _, client, _, _, _ = secret_setup

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post(payload)

        assert_that(exc_info.value.response.status_code).is_equal_to(400)
        assert_that(exc_info.value.response.json()).is_equal_to({"code": "INVALID_REQUEST", "detail": detail})

    async def it_dispenses_write_credentials_for_read_write_role(secret_setup) -> None:
        expected, client, _, auth_write, mock_credentials_manager = secret_setup
        credential = Credential(
            env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
            expiration=None,
        )
        auth_write.authorize(expected.account_id)
        mock_credentials_manager.fetch_credentials = return_responses(credential)

        result = await client.post({"account_id": expected.account_id, "role": "ReadWrite"})

        assert_that(result).is_equal_to({expected.account_id: dataclasses.asdict(credential)})
