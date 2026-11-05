package main

import (
	"os"

	"github.com/spf13/cobra"
)

const fence = "```"

func inContainer() bool {
	for _, p := range []string{"/run/.containerenv", "/.dockerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

const learnCommon = `
## Rules
- Never print, echo, log or paste a secret value. Check with ` + "`lockbox has`/`lockbox check`" + `, not ` + "`lockbox get`" + `.
- Give each command only the secrets it needs (` + "`--only`/`--as`/`-p`" + `). Plain ` + "`lockbox run`" + ` injects EVERY secret.
- Pass a secret into a container by name (` + "`podman run -e NAME`" + `), not as ` + "`-e NAME=$VALUE`" + ` (the value would sit in the process list and in ` + "`podman inspect`" + `).
- Store values with ` + "`--stdin`/`--file`" + `, not on the command line.
`

const learnHost = `# Lockbox - secrets for AI agents

Lockbox keeps secrets encrypted and injects them into a command's environment.
You normally never need to read a value.

## Look up what exists (names only)
` + fence + `bash
lockbox list --grep wallet          # keys matching a pattern
lockbox list --json                 # with created/updated times
lockbox has API_TOKEN MAIN_WALLET_KEY && echo ready   # exit 0 if all set and non-empty
lockbox check MAIN_WALLET_KEY       # length, shape (e.g. 0x-hex 32 bytes), warnings; never the value
` + fence + `

## Run a command with only the secrets it needs
` + fence + `bash
lockbox run --only API_TOKEN -c 'curl -s -H "Authorization: Bearer $API_TOKEN" https://api.example.com/v1/me'
lockbox run --as PAYER_KEY=MAIN_WALLET_KEY -- node pay.js     # rename on injection
lockbox run --only API_TOKEN --redact -c './script.sh'          # mask values in output as ***NAME***
lockbox run -p myproject -- make test                             # saved profile
` + fence + `
- A missing key aborts before the command starts.
- Without --only/--as/-p, every secret is injected (old behaviour); avoid that.
- --redact changes stdout/stderr (values of 8+ bytes become ***NAME***). Do not use it when stdout is a secret you need to capture.
- Profiles: ` + "`lockbox profile set NAME --only A,B --as X=Y --redact`" + `, ` + "`profile list|show|delete`" + `.

## Store or change a secret
` + fence + `bash
printf %s "$VALUE" | lockbox set API_KEY --stdin     # or: --file path
lockbox set API_KEY --file /dev/shm/key --trim --no-overwrite
lockbox history API_KEY       # previous values are kept (last 5)
lockbox rollback API_KEY      # restore the previous value (also undoes a delete)
` + fence + `
- --stdin/--file drop one trailing newline; --trim strips all surrounding whitespace.
- An empty value is refused (--allow-empty overrides).
` + learnCommon + `
## Only when you must read a raw value
` + "`lockbox get KEY`" + ` prints it to stdout, into your own context. Prefer ` + "`run`" + `.
`

const learnContainer = `# Lockbox - secrets for AI agents (container / remote mode)

You are in an isolated container. The host runs ` + "`lockbox serve`" + `; you cannot read its database, only ask the server (--remote). Names below assume the host is host.containers.internal:8100.

## Look up what exists (names only)
` + fence + `bash
lockbox list --remote host.containers.internal:8100 --grep wallet
lockbox has --remote host.containers.internal:8100 API_TOKEN && echo ready
lockbox check --remote host.containers.internal:8100 API_TOKEN   # length and shape, never the value
` + fence + `

## Run a command with only the secrets it needs
` + fence + `bash
lockbox run --remote host.containers.internal:8100 --only API_TOKEN -- npm test
lockbox run --remote host.containers.internal:8100 --as PAYER_KEY=MAIN_WALLET_KEY --redact -- node pay.js
` + fence + `
Without --only/--as every secret the server holds is fetched and injected.

## If the connection fails
1. The server may not be running: ask the user to run ` + "`lockbox serve --port 8100`" + ` on the host.
2. Check: curl http://host.containers.internal:8100/health
3. Storing, deleting and profiles work only on the host, not remotely.
` + learnCommon

func newLearnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "learn",
		Short: "Print instructions for AI agents on how to use lockbox",
		Long: `Print usage instructions for AI agents. Inside a container (or with
LOCKBOX_LEARN=container) it describes the remote-server workflow; on the host
(or with LOCKBOX_LEARN=host) it describes local scoped use.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			mode := os.Getenv("LOCKBOX_LEARN")
			if mode == "container" || (mode == "" && inContainer()) {
				os.Stdout.WriteString(learnContainer)
			} else {
				os.Stdout.WriteString(learnHost)
			}
		},
	}
}
