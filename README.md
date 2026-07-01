# ai-contained-provider-aws-secrets

Dispenses short-lived AWS credentials to authorized consumers (e.g. [`ai-contained-provider-aws-cli`](https://github.com/AI-Contained/ai-contained-provider-aws-cli)) via the trust-server protocol. Manages the AWS auth lifecycle (SSO login, credential validation, cache) and exposes account metadata to the AI via MCP. Does **not** run AWS commands itself — that's the CLI provider's job.

## MCP surface

- **Tool `aws_auth_read`** — elicits the user for ReadOnly access to an account, drives the SSO login flow if needed, and marks the account authorized for the current session.
- **Tool `aws_auth_write`** — same as above for ReadWrite.
- **Resource `ai-contained://aws-secrets/accounts`** — JSON listing of configured accounts (`account_id`, `name`, `has_read_only`, `has_read_write`). The AI reads this to discover what accounts exist.
- **HTTP route `POST /aws/secret`** — trust-server endpoint that returns short-lived credentials for an authorized `(account_id, role)` pair. Not called directly by the AI.

## Configuration

### Accounts file (JSON5)

Path is set via `AWS_ACCOUNTS_CONFIG_PATH`. If the env var is unset or empty, the provider silently doesn't register — useful for base images that ship the provider but don't always enable it.

```json5
{
  // Default login behaviour — applied to any account that doesn't specify its own.
  login: { type: "sso" },
  accounts: {
    "111111111111": {
      name: "SandboxAccount",
      read_profile: "sandbox-read",
      write_profile: "sandbox-write",
    },
    "222222222222": {
      name: "SharedAccount",
      read_profile: "shared-read",
      // credentials managed externally (instance profile, env vars, etc.):
      login: { type: "preauth" },
    },
  },
}
```

Per-account `login` fully overrides the top-level default. `AWS_PROFILE` is injected by the provider at runtime (set to `read_profile` or `write_profile`).

### Login types

| Type | Behavior |
|---|---|
| `sso` | Runs `aws sso login --no-browser`, surfaces the device URL via elicitation, re-validates on user confirmation. |
| `preauth` | Credentials assumed externally valid (e.g. instance profile, env vars); validate only. |
| `disabled` | Account visible in the resource but `aws_auth_*` always rejects. |
| `mfa` | *(future)* Elicit `MFA_TOKEN`, inject as env var, run command. |

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `AWS_ACCOUNTS_CONFIG_PATH` | for the provider to register | Path to the JSON5 accounts file. Absence = provider is a no-op. |
| `AWS_HOME` | no | Overrides `HOME` for AWS subprocesses only (`aws sso login`, `aws sts …`, `aws configure export-credentials`). Defaults to `dirname(AWS_ACCOUNTS_CONFIG_PATH)`. Lets `~/.aws/config`, `~/.aws/credentials`, and `~/.aws/sso/cache/` persist on a bind-mounted volume without relocating the whole container's `HOME`. Drop when [aws/aws-cli#9031](https://github.com/aws/aws-cli/issues/9031) ships. |
| `COLOR` | no | Set to any value other than `ascii` (e.g. `off`) to disable ANSI colours in elicitation messages. Default: `ascii` (colours on). |

## Directory layout

Recommended secrets bind mount, with `AWS_ACCOUNTS_CONFIG_PATH=/secrets/aws-secrets/accounts.json5`:

```
/secrets/aws-secrets/
├── accounts.json5              # this provider reads this
├── .aws/                       # AWS CLI reads/writes here (HOME=/secrets/aws-secrets)
│   ├── config                  # profile definitions, sso_session
│   ├── credentials             # long-lived creds if any (optional)
│   └── sso/
│       └── cache/              # SSO device tokens (persist across container runs)
```

## docker-compose example

```yaml
services:
  ai-contained:
    environment:
      - AWS_ACCOUNTS_CONFIG_PATH=/secrets/aws-secrets/accounts.json5
      # AWS_HOME defaults to dirname(AWS_ACCOUNTS_CONFIG_PATH) = /secrets/aws-secrets
    user: "${USER_ID:?USER_ID not set - run via ai-contained.sh}:${GROUP_ID:?GROUP_ID not set - run via ai-contained.sh}"
    volumes:
      - "${AI_CONTAINED_SECRETS_HOME:?AI_CONTAINED_SECRETS_HOME not set - run via ai-contained.sh}:/secrets"
```

## Advanced

### Overriding the shell commands per account

Each `login` block accepts three optional shell commands. All run via `sh -c` with `AWS_PROFILE` and the resolved `HOME` (see `AWS_HOME`) injected into their environment.

| Field | Default | Purpose |
|---|---|---|
| `command` | `aws sso login --no-browser` | The login flow (SSO only). Its stdout is captured and surfaced to the user via elicitation until two `https://…` URLs have been emitted. |
| `check_command` | `aws sts get-caller-identity --output json` | Validates existing credentials. Must exit `0` and emit JSON with an `"Account"` key matching the configured `account_id`. |
| `fetch_command` | `aws configure export-credentials --format env` | Emits `export KEY=VALUE` lines for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and optionally `AWS_CREDENTIAL_EXPIRATION`. |

Example — an account that uses a wrapper script instead of `aws sso login`:

```json5
"333333333333": {
  name: "CustomLoginAccount",
  read_profile: "custom-read",
  login: {
    type: "sso",
    command: "/opt/company/bin/custom-sso-login --profile custom-read",
  },
},
```

## Development

```bash
uv sync --extra dev

# Run tests
uv run --extra dev pytest -v

# Lint + format check
uv run --extra dev ruff check src/ tests/
uv run --extra dev ruff format --check src/ tests/

# Type check
uv run --extra dev mypy src/
```
