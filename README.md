# Lockbox

A secure secret management CLI for developers and AI agents. Encrypt secrets instead of leaving them in plain-text .env files.

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
lockbox run -- node server.js
# Secrets are injected into environment variables
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

### `lockbox set KEY VALUE`

Store a secret. Values are encrypted before storage.

```bash
lockbox set API_KEY "sk-xxxxx"
lockbox set DATABASE_URL "postgres://user:pass@localhost/mydb"
lockbox set WEBHOOK_SECRET "whsec_1234567890abcdef"
```

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

### `lockbox list`

List all secret keys (not values). Useful for auditing what's stored.

```bash
lockbox list
# Keys:
# - API_KEY
# - DATABASE_URL
# - WEBHOOK_SECRET
```

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

### `lockbox run -- COMMAND [ARGS...]`

Execute a command with secrets injected into its environment.

```bash
lockbox run -- node server.js
lockbox run -- python script.py --verbose
lockbox run -- npm test

# With --remote flag for server mode
lockbox run --remote http://lockbox-server:8080 -- bash deploy.sh
```

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
# Run command with remote secrets
lockbox run --remote localhost:8100 -- npm test

# Load remote secrets into shell
eval $(lockbox env --remote localhost:8100)
```

## Security Model

### How It Works

- **Encryption**: All secret values are encrypted with **AES-256-GCM** before being written to disk
- **Key storage**: A random encryption key is generated at init and stored in the database
- **Obfuscation model**: This provides protection against casual reading, not against determined attackers with full DB access
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
