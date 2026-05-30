from enum import StrEnum
from typing import Annotated

AwsAccountId = Annotated[str, "12-digit AWS account ID"]


class Role(StrEnum):
    READ_ONLY = "ReadOnly"
    READ_WRITE = "ReadWrite"
