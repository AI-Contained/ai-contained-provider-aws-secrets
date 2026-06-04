class MockCredentialsManager:
    async def validate(self, role, account):
        raise NotImplementedError("set mock_credentials_manager.validate = return_responses(...)")

    async def login(self, ctx, role, account):
        raise NotImplementedError("set mock_credentials_manager.login = return_responses(...)")

    async def fetch_credentials(self, role, account):
        raise NotImplementedError("set mock_credentials_manager.fetch_credentials = return_responses(...)")


def return_responses(*values):
    it = iter(values)

    async def _fn(*args, **kwargs):
        val = next(it)
        if isinstance(val, Exception):
            raise val
        return val

    return _fn
