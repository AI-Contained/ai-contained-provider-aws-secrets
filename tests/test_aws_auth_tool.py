from assertpy import assert_that

from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool
from ai_contained.provider.aws_secrets.types import Role


def describe_AwsAuthTool():
    def describe_is_authorized():
        def it_returns_false_by_default() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            assert_that(tool.is_authorized("123456789012")).is_false()

        def it_returns_false_after_revoke() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            tool.authorize("123456789012")
            assert_that(tool.is_authorized("123456789012")).is_true()
            tool.revoke("123456789012")
            assert_that(tool.is_authorized("123456789012")).is_false()

        def it_returns_false_after_revoke_all() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            tool.authorize("123456789012")
            assert_that(tool.is_authorized("123456789012")).is_true()
            tool.revoke_all()
            assert_that(tool.is_authorized("123456789012")).is_false()

        def it_is_idempotent_when_authorizing_twice() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            tool.authorize("123456789012")
            tool.authorize("123456789012")
            assert_that(tool.is_authorized("123456789012")).is_true()

    def describe_revoke():
        def it_does_not_raise_when_revoking_unknown_account() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            tool.revoke("123456789012")
            assert_that(tool.is_authorized("123456789012")).is_false()

        def it_only_revokes_target_account() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            tool.authorize("123456789012")
            tool.authorize("456789012345")
            assert_that(tool.is_authorized("123456789012")).is_true()
            assert_that(tool.is_authorized("456789012345")).is_true()
            tool.revoke("123456789012")
            assert_that(tool.is_authorized("123456789012")).is_false()
            assert_that(tool.is_authorized("456789012345")).is_true()

        def it_revoke_all_clears_all_accounts() -> None:
            tool = AwsAuthTool(Role.READ_ONLY)
            tool.authorize("123456789012")
            tool.authorize("456789012345")
            assert_that(tool.is_authorized("123456789012")).is_true()
            assert_that(tool.is_authorized("456789012345")).is_true()
            tool.revoke_all()
            assert_that(tool.is_authorized("123456789012")).is_false()
            assert_that(tool.is_authorized("456789012345")).is_false()
