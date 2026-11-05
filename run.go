package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "1.1.0"

func newRunCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "run [-c script | -- command [args...]]",
		Short: "Run a command with secrets in environment",
		Long: `Execute a command with stored secrets set as environment variables.

Shell mode (-c): runs the script via sh -c, so variable expansion works:
  lockbox run -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com'

Direct mode (--): runs the command directly without a shell:
  lockbox run -- ./my-app

Without scoping options EVERY stored secret is injected. Scope it:
  --only A,B          inject only these keys (error if one is missing)
  --as NEW=STORED     inject STORED under the name NEW (also scopes)
  --all               with --as/--only: also inject everything else
  -p, --profile NAME  apply a saved profile (see: lockbox profile --help)
  --redact            mask injected secret values in the command's stdout and
                      stderr as ***NAME*** (also LOCKBOX_REDACT=1)

  lockbox run --only API_TOKEN --redact -c 'curl -s -H "Authorization: Bearer $API_TOKEN" https://api.example.com/v1/me'
  lockbox run --as PAYER_KEY=MAIN_WALLET_KEY -- node pay.js

Redaction needs the output to pass through lockbox, so the child sees pipes
instead of a terminal, and values shorter than 8 bytes are not masked. It also
alters stdout, so do not use it when stdout carries a secret you need.`,
		TraverseChildren: true,
		Run: func(cmd *cobra.Command, args []string) {
			remote, _ := cmd.Flags().GetString("remote")
			shellScript, _ := cmd.Flags().GetString("cmd")
			profName, _ := cmd.Flags().GetString("profile")
			onlyRaw, _ := cmd.Flags().GetStringArray("only")
			asRaw, _ := cmd.Flags().GetStringArray("as")
			all, _ := cmd.Flags().GetBool("all")
			redact, _ := cmd.Flags().GetBool("redact")

			if shellScript != "" && len(args) > 0 {
				fatal("cannot use -c flag together with -- command")
			}
			if shellScript == "" && len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Error: no command provided\n")
				fmt.Fprintf(os.Stderr, "Usage: lockbox run -c 'echo $SECRET_VAR'\n")
				fmt.Fprintf(os.Stderr, "   or: lockbox run -- command [args...]\n")
				os.Exit(1)
			}

			as, err := parseAs(asRaw)
			if err != nil {
				fatal("%v", err)
			}
			sc := scope{only: splitList(onlyRaw), as: as, all: all, redact: redact}
			if v := os.Getenv("LOCKBOX_REDACT"); v == "1" || strings.EqualFold(v, "true") {
				sc.redact = true
			}
			if profName != "" {
				p, err := loadProfile(profName)
				if err != nil {
					fatal("%v", err)
				}
				sc = mergeScope(p, sc)
			}

			src, err := newSource(remote)
			if err != nil {
				fatal("%v", err)
			}
			r, err := resolve(src, sc)
			src.Close()
			if err != nil {
				fatal("%v", err)
			}

			env := os.Environ()
			for name, value := range r.env {
				env = append(env, name+"="+value)
			}

			var execCmd *exec.Cmd
			if shellScript != "" {
				execCmd = exec.Command("sh", "-c", shellScript)
			} else {
				execCmd = exec.Command(args[0], args[1:]...)
			}
			execCmd.Env = env
			execCmd.Stdin = os.Stdin
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr

			var flushers []*redactWriter
			if sc.redact {
				needles := buildNeedles(r.env)
				ow := newRedactWriter(os.Stdout, needles)
				ew := newRedactWriter(os.Stderr, needles)
				execCmd.Stdout, execCmd.Stderr = io.Writer(ow), io.Writer(ew)
				flushers = []*redactWriter{ow, ew}
			}

			err = execCmd.Run()
			for _, f := range flushers {
				f.Flush()
			}
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				fatal("failed to execute command: %v", err)
			}
		},
	}
	c.Flags().StringP("remote", "r", "", "Remote server to fetch secrets from (e.g., localhost:8100)")
	c.Flags().StringP("cmd", "c", "", "Shell script to execute (runs via sh -c, enabling $VAR expansion)")
	c.Flags().StringArrayP("only", "o", nil, "inject only these keys (comma-separated, repeatable)")
	c.Flags().StringArray("as", nil, "NEW_NAME=STORED_KEY: inject STORED_KEY under NEW_NAME")
	c.Flags().Bool("all", false, "with --only/--as: also inject all other secrets")
	c.Flags().StringP("profile", "p", "", "apply a saved profile")
	c.Flags().Bool("redact", false, "mask injected secret values in output")
	return c
}
