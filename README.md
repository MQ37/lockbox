# Lockbox

A secure secret management CLI for developers and AI agents. Encrypt secrets instead of leaving them in plain-text .env files.

> **🤖 AI Agents:** Run `lockbox learn` for usage instructions tailored to your environment.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)

> **⚠️ Disclaimer:** Lockbox does not provide true cryptographic security for your secrets. The secrets are encrypted but the encryption key is stored alongside the data. The primary goal is to make secrets **harder to read by AI agents and automated tools**, preventing accidental exposure through casual file reads. This is security through obscurity, not a replacement for proper secret management solutions.

## Why Lockbox?

### The Problem with .env Files

`.env` files are the industry standard for managing secrets, but they come with serious risks:

- **AI agents and scripts can read them easily** - Any tool with filesystem access can extract all your secrets with `cat .env`
- **Accidental exposure** - Developers frequently commit .env files to version control, leak them in logs, or expose them in containers
- **No access control** - All secrets are readable by any process running as the same user
- **Plain text at rest** - Secrets sit unencrypted on disk

### The Solution: Lockbox

Lockbox stores secrets in an encrypted SQLite database, making it fundamentally harder for tools to casually extract secrets:

- ✅ Secrets encrypted with **AES-256-GCM** at rest
- ✅ No readable plain-text files to accidentally commit
- ✅ Simple CLI designed for automation
- ✅ Can't be compromised by `cat`, `grep`, or filesystem scanning
- ✅ Server mode for remote/shared access

Perfect for:
- CI/CD pipelines protecting against malicious dependencies
- AI agents and LLMs that need secrets without exposing them
- Development teams that want tighter secret management
- Scripts that need to load secrets programmatically

## Installation

### Via `go install` (Recommended)

```bash
go install github.com/MQ37/lockbox@latest
```

Ensure your `$GOPATH/bin` is in your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Manual Installation

Download the latest binary from [Releases](https://github.com/MQ37/lockbox/releases):

```bash
# macOS
wget https://github.com/MQ37/lockbox/releases/download/v1.0.0/lockbox-darwin-arm64
chmod +x lockbox-darwin-arm64
sudo mv lockbox-darwin-arm64 /usr/local/bin/lockbox

# Linux
wget https://github.com/MQ37/lockbox/releases/download/v1.0.0/lockbox-linux-amd64
chmod +x lockbox-linux-amd64
sudo mv lockbox-linux-amd64 /usr/local/bin/lockbox

# Windows (PowerShell)
# Download .exe from releases and add to PATH
```

## Quick Start

Initialize Lockbox (creates encrypted database):

```bash
lockbox init
```

Store a secret:

```bash
lockbox set API_KEY "sk-1234567890abcdef"
lockbox set DATABASE_URL "postgresql://user:pass@localhost/db"
```

Load secrets and run a command:

```bash
lockbox run -c 'echo $API_KEY'
# Shell mode: secrets are expanded as $VAR references

lockbox run -- node server.js
# Direct mode: secrets are injected into environment variables
```

List all secret keys:

```bash
lockbox list
```

Retrieve a secret:

```bash
lockbox get API_KEY
```

Export all secrets to shell environment:

```bash
eval $(lockbox env)
echo $API_KEY  # sk-1234567890abcdef
```

## Commands

### `lockbox init`

Initialize Lockbox and create the encrypted database.

```bash
lockbox init
# Creates ~/.lockbox/lockbox.db
```

### `lockbox set KEY [VALUE]`

Store a secret. The value comes from exactly one of the `VALUE` argument, `--stdin` or `--file`. Prefer `--stdin`/`--file`: a value on the command line shows up in the process list and shell history, and a value starting with `-` cannot be passed as an argument at all.

```bash
printf %s "$TOKEN" | lockbox set API_KEY --stdin
lockbox set API_KEY --file /dev/shm/token.txt --no-overwrite
lockbox set WEBHOOK_SECRET "whsec_1234567890abcdef"
```

- `--stdin`/`--file` drop one trailing newline (`--raw` keeps the input exactly); `--trim` strips all surrounding whitespace from any source.
- An empty value is refused (`--allow-empty` overrides), so a failed `$(command)` cannot blank a secret.
- Setting an existing key keeps the previous value; `--no-overwrite` refuses instead. See `history` and `rollback` below.

### `lockbox history KEY` / `lockbox rollback KEY`

The last 5 previous values of every key are kept (encrypted). `rollback` restores the newest one, swapping the current value into the history so it can be undone; it also brings back a key removed by `delete`.

### `lockbox get KEY`

Retrieve and decrypt a secret. Prints the value to stdout.

```bash
lockbox get API_KEY
# Output: sk-xxxxx
```

### `lockbox delete KEY`

Delete a secret from the database.

```bash
lockbox delete OLD_SECRET
# Removed: OLD_SECRET
```

### `lockbox list [--grep PATTERN] [--json] [-v] [--remote URL]`

List secret keys (never values).

```bash
lockbox list                  # one key per line
lockbox list --grep wallet    # case-insensitive pattern; no match = no output, exit 1
lockbox list --json           # [{"key":..,"created_at":..,"updated_at":..}]
lockbox list -v               # key and last-updated time
```

### `lockbox has KEY...` and `lockbox check KEY...`

Inspect secrets without reading them.

```bash
lockbox has API_TOKEN MAIN_WALLET_KEY && echo ready   # prints nothing; exit 1 if any is missing or empty
lockbox check MAIN_WALLET_KEY
# MAIN_WALLET_KEY: set, length 64, hex, 32 bytes WITHOUT 0x prefix, updated 2026-01-15T09:30:00Z UTC
```

`check` reports the length, a coarse shape class (EVM key/address shape, Solana key length, URL scheme, known token prefix such as `ghp_`, PEM, JWT-like), the last-updated time and warnings (trailing newline, surrounding spaces, multi-line). It never prints any part of the value. `--json` for machine output; `--remote` works for both.

### `lockbox env [--remote URL]`

Export all secrets as shell-compatible environment variable assignments.

```bash
lockbox env
# export API_KEY='sk-xxxxx'
# export DATABASE_URL='postgres://...'

eval $(lockbox env)  # Load into current shell
```

With `--remote` flag, fetch from a remote Lockbox server:

```bash
lockbox env --remote http://lockbox-server:8080
```

### `lockbox run [-c script | -- command [args...]]`

Execute a command with secrets injected into its environment. Supports two modes:

**Shell mode (`-c`)** — runs the script via `sh -c`, so `$VAR` expansion works:

```bash
lockbox run -c 'echo $API_KEY'
lockbox run -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com'
lockbox run -c 'mongosh "$DATABASE_URL"'
```

**Direct mode (`--`)** — runs the command directly without a shell:

```bash
lockbox run -- node server.js
lockbox run -- python script.py --verbose
lockbox run -- npm test
```

With `--remote` flag for server mode:

```bash
lockbox run --remote http://lockbox-server:8080 -c 'echo $SECRET_VAR'
lockbox run --remote http://lockbox-server:8080 -- bash deploy.sh
```

> **Note:** The `-c` and `--` modes are mutually exclusive — you cannot use both at the same time.

**Scope what the command can see.** Without options `run` injects *every* stored secret. Narrow it:

```bash
lockbox run --only API_TOKEN -c 'curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/v1/me'
lockbox run --only A,B -- ./deploy.sh                       # a missing key aborts before the command starts
lockbox run --as PAYER_KEY=MAIN_WALLET_KEY -- node pay.js   # inject under another name (also scopes)
lockbox run --all --as CI_TOKEN=NPM_TOKEN -- ./job.sh      # everything, plus an alias
lockbox run -p myproject -- make test                      # saved profile (below)
```

**Redact output.** `--redact` (or `LOCKBOX_REDACT=1`) masks the injected values in the command's stdout and stderr as `***NAME***`, including base64 and URL-escaped forms, each line of multi-line values, and values split across output chunks:

```bash
lockbox run --only API_TOKEN --redact -c 'env | grep API_'   # API_TOKEN=***API_TOKEN***
```

Limits: values shorter than 8 bytes are not masked; the child sees pipes instead of a terminal; and because it rewrites stdout, do not use it when stdout carries a secret you need to capture. It is opt-in for that reason.

### `lockbox profile`

A profile is a saved set of `--only`/`--as`/`--all`/`--redact` options (key names only, no values), so a project always gets exactly its own secrets:

```bash
lockbox profile set myapp --only MAIN_WALLET_KEY,BACKUP_WALLET_KEY --as PAYER_KEY=MAIN_WALLET_KEY --redact
lockbox run -p myapp -- go test ./...
lockbox profile list | show NAME | delete NAME
```

Flags given on the command line are added on top of the profile.

### `lockbox serve [--port PORT]`

Start an HTTP server for remote secret access. Server binds to `localhost` only.

```bash
lockbox serve
# Server listening on http://127.0.0.1:8100

lockbox serve --port 9000
# Server listening on http://127.0.0.1:9000
```

## Server Mode

Lockbox can run as an HTTP server, allowing multiple machines or processes to access the same encrypted secret store.

### Starting a Server

```bash
lockbox serve --port 8100
# Server listening on http://127.0.0.1:8100
```

### Server Endpoints

#### `GET /health`

Health check endpoint.

```bash
curl http://localhost:8100/health
# {"status":"ok"}
```

#### `GET /secrets`

List all secret keys as JSON array.

```bash
curl http://localhost:8100/secrets
# ["API_KEY", "DATABASE_URL", "WEBHOOK_SECRET"]
```

#### `GET /secrets/:key`

Retrieve a decrypted secret value (plain text).

```bash
curl http://localhost:8100/secrets/API_KEY
# sk-xxxxx
```

#### `GET /env`

Export all secrets as shell environment variables.

```bash
curl http://localhost:8100/env
# export API_KEY="sk-xxxxx"
# export DATABASE_URL="postgres://..."
```

### Remote Usage

Point client commands to a remote server:

```bash
# Run command with remote secrets (shell mode)
lockbox run --remote localhost:8100 -c 'echo $API_KEY'

# Run command with remote secrets (direct mode)
lockbox run --remote localhost:8100 -- npm test

# Scoping, redaction, list/has/check also work remotely
lockbox run --remote localhost:8100 --only API_KEY -- npm test

# Load remote secrets into shell
eval $(lockbox env --remote localhost:8100)
```

## Security Model

### How It Works

- **Encryption**: All secret values are encrypted with **AES-256-GCM** before being written to disk
- **Key storage**: A random encryption key is generated at init and stored in the database
- **Obfuscation model**: This provides protection against casual reading, not against determined attackers with full DB access
- **File permissions**: the database file is created/kept at mode 0600
- **No authentication**: Server mode has no auth - relies on localhost binding for security
- **Server binding**: HTTP server binds to `127.0.0.1` only, preventing remote network access

### What Lockbox Protects Against

- Casual secret exposure via filesystem commands (`cat`, `grep`, `find`)
- AI agents and LLMs reading plain-text secret files
- Accidental commits of secrets to version control
- Simple string matching tools scanning disk
- Log file exposure from echoed .env contents

### What Lockbox Does NOT Protect Against

- Attackers with full filesystem access who can read the DB and key
- Memory dumping of running processes
- Network interception (server mode is HTTP, not HTTPS)
- Attackers who can execute arbitrary code in your environment

### Best Practices

1. **Restrict file permissions** - Keep `~/.lockbox/` readable only by your user:
   ```bash
   chmod 700 ~/.lockbox
   ```
2. **Use SSH tunnels for remote access** - Don't expose the server directly:
   ```bash
   ssh -L 8100:localhost:8100 user@remote-server
   lockbox env --remote localhost:8100
   ```
3. **Don't log secrets** - Avoid piping `lockbox get` output through shell history
4. **Rotate regularly** - Change sensitive secrets periodically

## Storage

Lockbox stores all data in a single SQLite database:

```
~/.lockbox/lockbox.db
```

The database contains:

- **secrets table** - Encrypted secret values (AES-256-GCM) with plaintext key names
- **config table** - Encryption key and metadata

### Backing Up Secrets

You can back up the database, but note that it contains the encryption key:

```bash
# Backup
cp ~/.lockbox/lockbox.db ./lockbox.db.backup

# Restore
cp ./lockbox.db.backup ~/.lockbox/lockbox.db
```

## Building

Builds and tests run in rootless podman, offline, with RAM-only scratch (the Go module cache is mounted read-only):

```bash
./build.sh test    # gofmt check, go vet, go test
./build.sh build   # static ./dist/lockbox
./build.sh         # both
```

## FAQ

**Q: Can I use Lockbox in CI/CD pipelines?**

A: Yes! Copy your `lockbox.db` to the CI environment or use server mode with SSH tunneling.

**Q: Is this production-ready?**

A: Lockbox is designed for development and automation secrets. For production (especially compliance-heavy environments), consider HashiCorp Vault, AWS Secrets Manager, or similar.

**Q: Can multiple users share the same Lockbox database?**

A: Yes, via server mode. Run `lockbox serve` on a shared machine and connect via SSH tunnel.

**Q: How do I migrate from .env files?**

A: Simple script:

```bash
lockbox init
while IFS='=' read -r key value; do
  [[ -n "$key" && ! "$key" =~ ^# ]] && lockbox set "$key" "$value"
done < .env
rm .env  # Delete the plain-text file
```

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/MQ37/lockbox).

## License

MIT License - see LICENSE file for details.
