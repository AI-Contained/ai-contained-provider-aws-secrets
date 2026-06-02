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
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"code": "INVALID_REQUEST", "detail": "request body must be valid JSON"}, status_code=400)

        account_id = body.get("account_id")
        role_str = body.get("role")

        if account_id is None:
            return JSONResponse({"code": "INVALID_REQUEST", "detail": "account_id is required"}, status_code=400)

        if role_str == "ReadOnly":
            auth_tool = self._auth_read
        elif role_str == "ReadWrite":
            auth_tool = self._auth_write
        else:
            return JSONResponse({"code": "INVALID_REQUEST", "detail": "role must be 'ReadOnly' or 'ReadWrite'"}, status_code=400)

        account = auth_tool.accounts.get_account(account_id)
        if account is None:
            return JSONResponse({"code": "UNKNOWN_ACCOUNT", "detail": f"Account '{account_id}' is not configured"}, status_code=404)

        if not auth_tool.is_authorized(account_id):
            return JSONResponse({"code": "NOT_AUTHORIZED", "detail": f"Call aws_auth('{account_id}') to authenticate, then retry"}, status_code=403)

        try:
            credential = await auth_tool.authenticator.fetch_credentials(auth_tool.role, account)
        except ToolError:
            return JSONResponse({"code": "SESSION_EXPIRED", "detail": f"Call aws_auth('{account_id}') to re-authenticate, then retry"}, status_code=401)

        return JSONResponse({account_id: dataclasses.asdict(credential)})
