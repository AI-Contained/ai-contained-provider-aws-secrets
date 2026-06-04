"""Shared type definitions for the AWS secrets provider."""

from enum import StrEnum
from typing import Annotated

AwsAccountId = Annotated[str, "12-digit AWS account ID"]


class Role(StrEnum):
    """Access level requested for an AWS account."""

    READ_ONLY = "ReadOnly"
    READ_WRITE = "ReadWrite"


class AccessStatus(StrEnum):
    """Authorization state of an account for a given role."""

    UNSUPPORTED = "unsupported"
    REQUIRES_AUTH = "requires_auth"
    AUTHORIZED = "authorized"


class LoginType(StrEnum):
    """Mechanism used to obtain credentials for an account."""

    SSO = "sso"
    PREAUTH = "preauth"
    DISABLED = "disabled"
    MFA = "mfa"
