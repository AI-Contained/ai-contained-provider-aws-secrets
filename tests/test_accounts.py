import pytest
from assertpy import assert_that

from ai_contained.provider.aws_secrets.accounts import Account, AccountLogin, Accounts
from ai_contained.provider.aws_secrets.types import Role


def assert_account(result: Account, expected: Account) -> None:
    assert_that(result.name).is_equal_to(expected.name)
    assert_that(result.trust_groups).is_equal_to(expected.trust_groups)
    assert_that(result.read_profile).is_equal_to(expected.read_profile)
    assert_that(result.write_profile).is_equal_to(expected.write_profile)
    assert_that(result.login).is_equal_to(expected.login)


def describe_Accounts():
    def describe_init():
        def it_parses_an_account() -> None:
            expected = Account(
                account_id="123456789012",
                name="StagingAlpha",
                trust_groups=["ProjectRocket"],
                read_profile="staging-alpha-read",
                write_profile="staging-alpha-write",
                login=AccountLogin(type="sso", command=None),
            )
            result = Accounts(f"""
            {{
                login: {{ type: "{expected.login.type}" }},
                accounts: {{
                    "{expected.account_id}": {{
                        name: "{expected.name}",
                        trust_groups: ["{expected.trust_groups[0]}"],
                        read_profile: "{expected.read_profile}",
                        write_profile: "{expected.write_profile}",
                    }},
                }},
            }}
            """).get_account(expected.account_id)
            assert_account(result, expected)

        def it_defaults_trust_groups_to_empty_list() -> None:
            expected = Account(
                account_id="123456789012",
                name="StagingAlpha",
                trust_groups=[],
                read_profile="staging-alpha-read",
                write_profile=None,
                login=AccountLogin(type="sso", command=None),
            )
            result = Accounts(f"""
            {{
                login: {{ type: "{expected.login.type}" }},
                accounts: {{
                    "{expected.account_id}": {{
                        name: "{expected.name}",
                        read_profile: "{expected.read_profile}",
                    }},
                }},
            }}
            """).get_account(expected.account_id)
            assert_account(result, expected)

        def it_propagates_root_login_to_accounts() -> None:
            expected = Account(
                account_id="123456789012",
                name="StagingAlpha",
                trust_groups=[],
                read_profile="staging-alpha-read",
                write_profile=None,
                login=AccountLogin(type="sso", command="aws sso login --no-browser"),
            )
            result = Accounts(f"""
            {{
                login: {{ type: "{expected.login.type}", command: "{expected.login.command}" }},
                accounts: {{
                    "{expected.account_id}": {{
                        name: "{expected.name}",
                        trust_groups: [],
                        read_profile: "{expected.read_profile}",
                    }},
                }},
            }}
            """).get_account(expected.account_id)
            assert_account(result, expected)

        def it_overrides_root_login_per_account() -> None:
            expected = Account(
                account_id="123456789012",
                name="StagingAlpha",
                trust_groups=[],
                read_profile="staging-alpha-read",
                write_profile=None,
                login=AccountLogin(type="preauth", command=None),
            )
            result = Accounts(f"""
            {{
                login: {{ type: "sso" }},
                accounts: {{
                    "{expected.account_id}": {{
                        name: "{expected.name}",
                        trust_groups: [],
                        read_profile: "{expected.read_profile}",
                        login: {{ type: "{expected.login.type}" }},
                    }},
                }},
            }}
            """).get_account(expected.account_id)
            assert_account(result, expected)

        def it_uses_account_login_when_no_root_login() -> None:
            expected = Account(
                account_id="123456789012",
                name="StagingAlpha",
                trust_groups=[],
                read_profile="staging-alpha-read",
                write_profile=None,
                login=AccountLogin(type="preauth", command=None),
            )
            result = Accounts(f"""
            {{
                accounts: {{
                    "{expected.account_id}": {{
                        name: "{expected.name}",
                        read_profile: "{expected.read_profile}",
                        login: {{ type: "{expected.login.type}" }},
                    }},
                }},
            }}
            """).get_account(expected.account_id)
            assert_account(result, expected)

        def it_errors_when_no_login_configured_for_account() -> None:
            with pytest.raises(KeyError, match="Account has no login and no root login is defined"):
                Accounts("""
                {
                    accounts: {
                        "123456789012": {
                            name: "StagingAlpha",
                            read_profile: "staging-alpha-read",
                        },
                    },
                }
                """)

        def it_errors_on_misspelled_login_type() -> None:
            with pytest.raises(KeyError, match="type"):
                Accounts("""
                {
                    login: { tpye: "sso" },
                    accounts: {},
                }
                """)

        def it_errors_on_misspelled_account_name() -> None:
            with pytest.raises(KeyError, match="name"):
                Accounts("""
                {
                    login: { type: "sso" },
                    accounts: {
                        "123456789012": {
                            nme: "StagingAlpha",
                            read_profile: "staging-alpha-read",
                        },
                    },
                }
                """)

        def it_errors_on_invalid_json5() -> None:
            with pytest.raises(ValueError, match="Unexpected"):
                Accounts("{ not valid json5 !!!}")

        def it_errors_on_missing_accounts_key() -> None:
            with pytest.raises(KeyError, match="Missing 'accounts' key in config"):
                Accounts("{ login: { type: 'sso' } }")

    def describe_get_account():
        def it_returns_none_for_unknown_id() -> None:
            result = Accounts("""
            {
                login: { type: "sso" },
                accounts: {},
            }
            """).get_account("000000000000")
            assert_that(result).is_none()

    def describe_get_group():
        def it_returns_accounts_in_group() -> None:
            expected = Account(
                account_id="123456789012",
                name="StagingAlpha",
                trust_groups=["ProjectRocket"],
                read_profile="staging-alpha-read",
                write_profile=None,
                login=AccountLogin(type="sso", command=None),
            )
            result = Accounts(f"""
            {{
                login: {{ type: "{expected.login.type}" }},
                accounts: {{
                    "{expected.account_id}": {{
                        name: "{expected.name}",
                        trust_groups: ["{expected.trust_groups[0]}"],
                        read_profile: "{expected.read_profile}",
                    }},
                }},
            }}
            """).get_group(expected.trust_groups[0])
            assert_that(result).is_length(1)
            assert_account(result[0], expected)

        def it_returns_empty_list_for_unknown_group() -> None:
            result = Accounts("""
            {
                login: { type: "sso" },
                accounts: {},
            }
            """).get_group("UnknownGroup")
            assert_that(result).is_empty()

        def it_excludes_disabled_accounts() -> None:
            result = Accounts("""
            {
                login: { type: "sso" },
                accounts: {
                    "123456789012": {
                        name: "StagingAlpha",
                        trust_groups: ["ProjectRocket"],
                        read_profile: "staging-alpha-read",
                        login: { type: "disabled" },
                    },
                },
            }
            """).get_group("ProjectRocket")
            assert_that(result).is_empty()

    def describe_all_accounts():
        def it_excludes_disabled_accounts() -> None:
            result = Accounts("""
            {
                login: { type: "sso" },
                accounts: {
                    "123456789012": {
                        name: "StagingAlpha",
                        trust_groups: [],
                        read_profile: "staging-alpha-read",
                    },
                    "456789012345": {
                        name: "Production",
                        trust_groups: [],
                        read_profile: "production-read",
                        login: { type: "disabled" },
                    },
                },
            }
            """).all_accounts()
            assert_that([a.name for a in result]).is_equal_to(["StagingAlpha"])


def describe_Account():
    def describe_profile_for():
        def _make_account(read_profile=None, write_profile=None):
            return Account(
                account_id="123456789012",
                name="Test",
                trust_groups=[],
                read_profile=read_profile,
                write_profile=write_profile,
                login=AccountLogin(type="sso", command=None),
            )

        def returns_read_profile_for_read_only_role() -> None:
            account = _make_account(read_profile="read-profile", write_profile="write-profile")
            assert_that(account.profile_for(Role.READ_ONLY)).is_equal_to("read-profile")

        def returns_write_profile_for_write_role() -> None:
            account = _make_account(read_profile="read-profile", write_profile="write-profile")
            assert_that(account.profile_for(Role.READ_WRITE)).is_equal_to("write-profile")

        def raises_when_read_profile_is_none() -> None:
            account = _make_account(read_profile=None)
            with pytest.raises(ValueError) as exc_info:
                account.profile_for(Role.READ_ONLY)
            assert_that(str(exc_info.value)).is_equal_to(
                f"no {Role.READ_ONLY} profile configured for account {account.account_id}"
            )

        def raises_when_write_profile_is_none() -> None:
            account = _make_account(write_profile=None)
            with pytest.raises(ValueError) as exc_info:
                account.profile_for(Role.READ_WRITE)
            assert_that(str(exc_info.value)).is_equal_to(
                f"no {Role.READ_WRITE} profile configured for account {account.account_id}"
            )
