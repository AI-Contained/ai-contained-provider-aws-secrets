import pytest
from assertpy import assert_that

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
    def auth_read():
        return AwsAuthTool(Role.READ_ONLY)

    @pytest.fixture
    def auth_write():
        return AwsAuthTool(Role.READ_WRITE)

    def describe_get():
        def it_includes_name_and_trust_groups(account_id, auth_read, auth_write) -> None:
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
                auth_read,
                auth_write,
            ).get()
            assert_account_entry(result.get(account_id), expected)

        def it_excludes_disabled_accounts(account_id, auth_read, auth_write) -> None:
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
                auth_read,
                auth_write,
            ).get()
            assert_that(result.get(account_id)).is_none()

        def it_reports_read_access_as_unavailable_when_no_read_profile_is_configured(account_id, auth_read, auth_write) -> None:
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
                auth_read,
                auth_write,
            ).get()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_read_access_as_pending_authorization(account_id, auth_read, auth_write) -> None:
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
                auth_read,
                auth_write,
            ).get()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_read_access_as_active_after_authorization(account_id, auth_write) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.AUTHORIZED,
                read_write=AccessStatus.UNSUPPORTED,
            )
            auth_read = AwsAuthTool(Role.READ_ONLY)
            auth_read.authorize(account_id)
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
                auth_read,
                auth_write,
            ).get()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_write_access_as_pending_authorization(account_id, auth_read, auth_write) -> None:
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
                auth_read,
                auth_write,
            ).get()
            assert_account_entry(result.get(account_id), expected)

        def it_reports_write_access_as_active_after_authorization(account_id, auth_read) -> None:
            expected = AwsAccountResourceEntry(
                name="StagingAlpha",
                trust_groups=[],
                read_only=AccessStatus.REQUIRES_AUTH,
                read_write=AccessStatus.AUTHORIZED,
            )
            auth_write = AwsAuthTool(Role.READ_WRITE)
            auth_write.authorize(account_id)
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
                auth_read,
                auth_write,
            ).get()
            assert_account_entry(result.get(account_id), expected)
