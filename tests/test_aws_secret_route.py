import dataclasses

import httpx
import pytest
from assertpy import assert_that
from fastmcp.exceptions import ToolError

from ai_contained.provider.aws_secrets.credentials_manager import Credential

from conftest import ACCOUNT_ID, return_responses


def describe_AwsSecretRoute():
    async def it_dispenses_credentials_to_authorized_callers(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        expected = Credential(
            env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
            expiration="2026-06-01T11:12:44+00:00",
        )
        auth_read.authorize(ACCOUNT_ID)
        mock_credentials_manager.fetch_credentials = return_responses(expected)
        result = await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
        assert_that(result).is_equal_to({ACCOUNT_ID: dataclasses.asdict(expected)})

    async def it_dispenses_credentials_without_expiration(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        expected = Credential(
            env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
            expiration=None,
        )
        auth_read.authorize(ACCOUNT_ID)
        mock_credentials_manager.fetch_credentials = return_responses(expected)
        result = await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
        assert_that(result).is_equal_to({ACCOUNT_ID: dataclasses.asdict(expected)})

    async def it_blocks_unauthorized_callers(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
        assert_that(exc_info.value.response.json()).is_equal_to({
            "code": "NOT_AUTHORIZED",
            "detail": f"Call aws_auth_read('{ACCOUNT_ID}') to authenticate, then retry",
        })

    async def it_rejects_unknown_accounts(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post({"account_id": "000000000000", "role": "ReadOnly"})
        assert_that(exc_info.value.response.json()).is_equal_to({
            "code": "UNKNOWN_ACCOUNT",
            "detail": "Account '000000000000' is not configured",
        })

    async def it_signals_session_expired_when_credentials_are_unavailable(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        auth_read.authorize(ACCOUNT_ID)
        mock_credentials_manager.fetch_credentials = return_responses(ToolError("credentials unavailable"))
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post({"account_id": ACCOUNT_ID, "role": "ReadOnly"})
        assert_that(exc_info.value.response.json()).is_equal_to({
            "code": "SESSION_EXPIRED",
            "detail": f"Call aws_auth_read('{ACCOUNT_ID}') to re-authenticate, then retry",
        })

    @pytest.mark.skip(reason="malformed JSON is currently rejected by trust-server before reaching our handler — revisit")
    async def it_rejects_malformed_json(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        http = client._connection._http
        response = await http.post("/aws/secret", content=b"not-json", headers={"content-type": "application/json"})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_REQUEST")

    @pytest.mark.parametrize("payload,detail", [
        pytest.param({"role": "ReadOnly"}, "account_id is required", id="missing account_id"),
        pytest.param({"account_id": ACCOUNT_ID}, "role must be 'ReadOnly' or 'ReadWrite'", id="missing role"),
        pytest.param({"account_id": ACCOUNT_ID, "role": "SuperAdmin"}, "role must be 'ReadOnly' or 'ReadWrite'", id="invalid role"),
    ])
    async def it_rejects_invalid_requests(secret_setup, payload, detail) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.post(payload)
        assert_that(exc_info.value.response.json()).is_equal_to({"code": "INVALID_REQUEST", "detail": detail})

    async def it_dispenses_write_credentials_for_read_write_role(secret_setup) -> None:
        client, auth_read, auth_write, mock_credentials_manager = secret_setup
        expected = Credential(
            env={"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "SECRET", "AWS_SESSION_TOKEN": "TOKEN"},
            expiration=None,
        )
        auth_write.authorize(ACCOUNT_ID)
        mock_credentials_manager.fetch_credentials = return_responses(expected)
        result = await client.post({"account_id": ACCOUNT_ID, "role": "ReadWrite"})
        assert_that(result).is_equal_to({ACCOUNT_ID: dataclasses.asdict(expected)})
