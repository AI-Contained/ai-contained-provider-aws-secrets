from collections.abc import AsyncGenerator

import httpx
import pytest
from fastmcp import FastMCP

from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection
from ai_contained.trust.server.trust_store import get_trust_store

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role


ACCOUNT_ID = "123456789012"


def return_responses(*values):
    it = iter(values)
    async def _fn(*args, **kwargs):
        val = next(it)
        if isinstance(val, Exception):
            raise val
        return val
    return _fn


class MockCredentialsManager:
    async def validate(self, role, account):
        raise NotImplementedError("set mock_credentials_manager.validate = return_responses(...)")

    async def login(self, ctx, role, account):
        raise NotImplementedError("set mock_credentials_manager.login = return_responses(...)")

    async def fetch_credentials(self, role, account):
        raise NotImplementedError("set mock_credentials_manager.fetch_credentials = return_responses(...)")


@pytest.fixture
def mcp() -> FastMCP:
    return FastMCP("test")


@pytest.fixture
def aws_auth_read() -> AwsAuthTool:
    return AwsAuthTool(Role.READ_ONLY, Accounts('{ login: { type: "sso" }, accounts: {} }'))


@pytest.fixture
def aws_auth_write() -> AwsAuthTool:
    return AwsAuthTool(Role.READ_WRITE, Accounts('{ login: { type: "sso" }, accounts: {} }'))


@pytest.fixture
def accounts() -> Accounts:
    return Accounts(f"""{{
        login: {{ type: "sso" }},
        accounts: {{ "{ACCOUNT_ID}": {{ name: "Test", read_profile: "test-read", write_profile: "test-write" }} }},
    }}""")


@pytest.fixture
async def secret_setup(accounts: Accounts) -> AsyncGenerator:
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
        yield TrustClient(_connection=conn, _path="/aws/secret"), auth_read, auth_write, mock_credentials_manager
