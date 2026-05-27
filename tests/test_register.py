from fastmcp import FastMCP

from ai_contained.provider.aws_secrets import register


def describe_register() -> None:
    async def it_registers_without_error(mcp: FastMCP) -> None:
        await register(mcp)
