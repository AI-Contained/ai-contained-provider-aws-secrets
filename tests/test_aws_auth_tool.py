import pytest
from assertpy import assert_that

from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role


def describe_AwsAuthTool():
    def describe_is_authorized():
        def it_returns_false_by_default() -> None:
            tool = AwsAuthTool()
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_false()

        def it_returns_true_after_authorize() -> None:
            tool = AwsAuthTool()
            tool.authorize("123456789012", Role.READ_ONLY)
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_true()

        @pytest.mark.parametrize("authorized,checked", [
            (Role.READ_ONLY,  Role.READ_WRITE),
            (Role.READ_WRITE, Role.READ_ONLY),
        ])
        def it_does_not_grant_other_role(authorized: Role, checked: Role) -> None:
            tool = AwsAuthTool()
            tool.authorize("123456789012", authorized)
            assert_that(tool.is_authorized("123456789012", authorized)).is_true()
            assert_that(tool.is_authorized("123456789012", checked)).is_false()

        def it_returns_false_after_revoke() -> None:
            tool = AwsAuthTool()
            tool.authorize("123456789012", Role.READ_ONLY)
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_true()
            tool.revoke("123456789012")
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_false()

        def it_returns_false_after_revoke_all() -> None:
            tool = AwsAuthTool()
            tool.authorize("123456789012", Role.READ_ONLY)
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_true()
            tool.revoke_all()
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_false()

    def describe_revoke():
        def it_only_revokes_target_account() -> None:
            tool = AwsAuthTool()
            tool.authorize("123456789012", Role.READ_ONLY)
            tool.authorize("456789012345", Role.READ_ONLY)
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_true()
            assert_that(tool.is_authorized("456789012345", Role.READ_ONLY)).is_true()
            tool.revoke("123456789012")
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_false()
            assert_that(tool.is_authorized("456789012345", Role.READ_ONLY)).is_true()

        def it_revoke_all_clears_all_accounts() -> None:
            tool = AwsAuthTool()
            tool.authorize("123456789012", Role.READ_ONLY)
            tool.authorize("456789012345", Role.READ_WRITE)
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_true()
            assert_that(tool.is_authorized("456789012345", Role.READ_WRITE)).is_true()
            tool.revoke_all()
            assert_that(tool.is_authorized("123456789012", Role.READ_ONLY)).is_false()
            assert_that(tool.is_authorized("456789012345", Role.READ_WRITE)).is_false()
