import dataclasses

from fastmcp.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ai_contained.provider.aws_secrets.aws_auth_tool import AwsAuthTool


class AwsSecretRoute:
    def __init__(self, auth_read: AwsAuthTool, auth_write: AwsAuthTool) -> None:
        self._auth_read = auth_read
        self._auth_write = auth_write

    async def handle(self, request: Request) -> Response:
        raise NotImplementedError
