import json
from collections.abc import AsyncGenerator

import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import FastMCPTransport

from ai_contained.provider.aws_secrets import register
from ai_contained.provider.aws_secrets.accounts import Accounts
from ai_contained.provider.aws_secrets.aws_accounts_resource import AwsAccountResourceEntry, AwsAccountsResource
from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import AccessStatus, Role


def assert_account_entry(result: AwsAccountResourceEntry | None, expected: AwsAccountResourceEntry) -> None:
    assert_that(result).is_not_none()
    assert_that(result.name).is_equal_to(expected.name)
    assert_that(result.trust_groups).is_equal_to(expected.trust_groups)
    assert_that(result.read_only).is_equal_to(expected.read_only)
    assert_that(result.read_write).is_equal_to(expected.read_write)


def describe_AwsAccountsResource():
    @pytest.fixture
    def account_id():
        return "123456789012"

    @pytest.fixture
    def aws_auth_read() -> AwsAuthTool:
        return AwsAuthTool(Role.READ_ONLY, Accounts('{ login: { type: "sso" }, accounts: {} }'))

    @pytest.fixture
    def aws_auth_write() -> AwsAuthTool:
        return AwsAuthTool(Role.READ_WRITE, Accounts('{ login: { type: "sso" }, accounts: {} }'))



    def describe_convert():
        def it_includes_name_and_trust_groups(account_id, aws_auth_read, aws_auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=["ProjectRocket"],
                read_only=AccessStatus.REQUIRES_AUTH,
                read_write=AccessStatus.REQUIRES_AUTH,
            )
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "{expected.name}",
                            trust_groups: ["{expected.trust_groups[0]}"],
                            read_profile: "staging-alpha-read",
                            write_profile: "staging-alpha-write",
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_account_entry(result.get(account_id), expected)

        def it_excludes_disabled_accounts(account_id, aws_auth_read, aws_auth_write) -> None:
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "StagingAlpha",
                            trust_groups: [],
                            read_profile: "staging-alpha-read",
                            login: {{ type: "disabled" }},
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_that(result.get(account_id)).is_none()

        def it_reports_read_access_as_unavailable_when_no_read_profile_is_configured(account_id, aws_auth_read, aws_auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.UNSUPPORTED,
                read_write=AccessStatus.REQUIRES_AUTH,
            )
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "{expected.name}",
                            trust_groups: [],
                            write_profile: "staging-alpha-write",
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_read_access_as_pending_authorization(account_id, aws_auth_read, aws_auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.REQUIRES_AUTH,
                read_write=AccessStatus.UNSUPPORTED,
            )
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "{expected.name}",
                            trust_groups: [],
                            read_profile: "staging-alpha-read",
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_read_access_as_active_after_authorization(account_id, aws_auth_read, aws_auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.AUTHORIZED,
                read_write=AccessStatus.UNSUPPORTED,
            )
            aws_auth_read.authorize(account_id)
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "{expected.name}",
                            trust_groups: [],
                            read_profile: "staging-alpha-read",
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_write_access_as_pending_authorization(account_id, aws_auth_read, aws_auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.REQUIRES_AUTH,
                read_write=AccessStatus.REQUIRES_AUTH,
            )
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "{expected.name}",
                            trust_groups: [],
                            read_profile: "staging-alpha-read",
                            write_profile: "staging-alpha-write",
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_write_access_as_active_after_authorization(account_id, aws_auth_read, aws_auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.REQUIRES_AUTH,
                read_write=AccessStatus.AUTHORIZED,
            )
            aws_auth_write.authorize(account_id)
            result = AwsAccountsResource(
                Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "{expected.name}",
                            trust_groups: [],
                            read_profile: "staging-alpha-read",
                            write_profile: "staging-alpha-write",
                        }},
                    }},
                }}
                """),
                aws_auth_read,
                aws_auth_write,
            ).convert()
            assert_account_entry(result.get(account_id), expected)

    def describe_get():
        @pytest.fixture
        async def client(account_id: str, aws_auth_read: AwsAuthTool, aws_auth_write: AwsAuthTool) -> AsyncGenerator[Client[FastMCPTransport], None]:
            server = FastMCP("test")
            await register(
                server,
                _accounts=Accounts(f"""
                {{
                    login: {{ type: "sso" }},
                    accounts: {{
                        "{account_id}": {{
                            name: "StagingAlpha",
                            trust_groups: ["ProjectRocket"],
                            read_profile: "staging-alpha-read",
                            write_profile: "staging-alpha-write",
                        }},
                    }},
                }}
                """),
                _auth_read=aws_auth_read,
                _auth_write=aws_auth_write,
            )
            async with Client(transport=server) as c:
                yield c

        async def it_registers_the_resource(client: Client[FastMCPTransport]) -> None:
            resources = await client.list_resources()
            assert_that([str(r.uri) for r in resources]).contains("ai-contained://aws-secrets/accounts")

        async def it_reflects_authorization_state(client: Client[FastMCPTransport], account_id: str, aws_auth_read: AwsAuthTool) -> None:
            aws_auth_read.authorize(account_id)
            content = await client.read_resource("ai-contained://aws-secrets/accounts")
            data = json.loads(content[0].text)
            assert_that(data[account_id]["read_only"]).is_equal_to("authorized")