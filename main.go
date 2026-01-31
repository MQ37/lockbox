package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/MQ37/lockbox/internal/crypto"
	"github.com/MQ37/lockbox/internal/db"
	"github.com/spf13/cobra"
)

// getStoreAndKey opens the store and retrieves the encryption key
func getStoreAndKey() (*db.Store, []byte, error) {
	store, err := db.NewStore()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open store: %w", err)
	}

	keyHex, err := store.GetConfig("encryption_key")
	if err != nil {
		if err == db.ErrNotFound {
			return nil, nil, fmt.Errorf("encryption key not found. Please run 'lb init' first")
		}
		return nil, nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Decode hex-encoded key
	key, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	return store, key, nil
}

// fetchRemoteSecrets fetches secrets from a remote server
func fetchRemoteSecrets(remote string) (map[string]string, error) {
	url := fmt.Sprintf("http://%s/secrets", remote)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets from remote: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, body)
	}

	var keys []string
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode remote response: %w", err)
	}

	secrets := make(map[string]string)
	for _, key := range keys {
		valueURL := fmt.Sprintf("http://%s/secrets/%s", remote, key)
		valueResp, err := http.Get(valueURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch secret '%s' from remote: %w", key, err)
		}
		defer valueResp.Body.Close()

		if valueResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(valueResp.Body)
			return nil, fmt.Errorf("remote server returned status %d for '%s': %s", valueResp.StatusCode, key, body)
		}

		value, err := io.ReadAll(valueResp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret '%s' from remote: %w", key, err)
		}
		secrets[key] = string(value)
	}

	return secrets, nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "lb",
		Short: "Lockbox - A secure secret management CLI",
		Long:  `Lockbox is a command-line tool for securely storing and managing secrets.`,
	}

	// init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Lockbox",
		Long:  `Initialize Lockbox by creating the store and generating an encryption key.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Create store
			store, err := db.NewStore()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to create store: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Check if key already exists
			_, err = store.GetConfig("encryption_key")
			if err == nil {
				fmt.Println("Lockbox is already initialized. Encryption key already exists.")
				return
			}
			if err != db.ErrNotFound {
				fmt.Fprintf(os.Stderr, "Error: failed to check for existing key: %v\n", err)
				os.Exit(1)
			}

			// Generate encryption key
			key, err := crypto.GenerateKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to generate encryption key: %v\n", err)
				os.Exit(1)
			}

			// Store key as hex string
			keyHex := hex.EncodeToString(key)
			if err := store.SetConfig("encryption_key", []byte(keyHex)); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to store encryption key: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("✓ Lockbox initialized successfully")
		},
	}

	// set command
	setCmd := &cobra.Command{
		Use:   "set KEY VALUE",
		Short: "Set a secret",
		Long:  `Store a secret with the given key and value.`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			value := args[1]

			store, encKey, err := getStoreAndKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Encrypt the value
			encrypted, err := crypto.Encrypt([]byte(value), encKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to encrypt value: %v\n", err)
				os.Exit(1)
			}

			// Store the encrypted value
			if err := store.SetSecret(key, encrypted); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to store secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✓ Secret '%s' set successfully\n", key)
		},
	}

	// get command
	getCmd := &cobra.Command{
		Use:   "get KEY",
		Short: "Get a secret",
		Long:  `Retrieve and decrypt a secret by its key.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]

			store, encKey, err := getStoreAndKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Get the encrypted value
			encrypted, err := store.GetSecret(key)
			if err != nil {
				if err == db.ErrNotFound {
					fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", key)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Error: failed to get secret: %v\n", err)
				os.Exit(1)
			}

			// Decrypt the value
			decrypted, err := crypto.Decrypt(encrypted, encKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to decrypt secret: %v\n", err)
				os.Exit(1)
			}

			// Print just the value with no extra formatting
			fmt.Print(string(decrypted))
		},
	}

	// delete command
	deleteCmd := &cobra.Command{
		Use:   "delete KEY",
		Short: "Delete a secret",
		Long:  `Remove a secret by its key.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]

			store, _, err := getStoreAndKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Delete the secret
			if err := store.DeleteSecret(key); err != nil {
				if err == db.ErrNotFound {
					fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", key)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Error: failed to delete secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✓ Secret '%s' deleted successfully\n", key)
		},
	}

	// list command
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		Long:  `Display all stored secret keys.`,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Get all secrets
			keys, err := store.ListSecrets()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to list secrets: %v\n", err)
				os.Exit(1)
			}

			if len(keys) == 0 {
				fmt.Println("No secrets found")
				return
			}

			// Print each key on its own line
			fmt.Println(strings.Join(keys, "\n"))
		},
	}

	// env command - Export secrets as environment variables
	envCmd := &cobra.Command{
		Use:   "env",
		Short: "Export secrets as environment variables",
		Long: `Export all stored secrets in shell export format.
Can be used with eval or source to set environment variables:
  eval $(lb env)
  source <(lb env)`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			store, encKey, err := getStoreAndKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Get all secrets
			keys, err := store.ListSecrets()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to list secrets: %v\n", err)
				os.Exit(1)
			}

			// For each key, get and decrypt the value
			for _, key := range keys {
				encrypted, err := store.GetSecret(key)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: failed to get secret '%s': %v\n", key, err)
					os.Exit(1)
				}

				// Decrypt the value
				decrypted, err := crypto.Decrypt(encrypted, encKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: failed to decrypt secret '%s': %v\n", key, err)
					os.Exit(1)
				}

				// Escape the value: surround with double quotes and escape special chars
				value := string(decrypted)
				escapedValue := strings.NewReplacer(
					"\\", "\\\\",
					"\"", "\\\"",
					"$", "\\$",
					"`", "\\`",
				).Replace(value)

				fmt.Printf("export %s=\"%s\"\n", key, escapedValue)
			}
		},
	}

	// run command - Run a command with secrets in environment
	runCmd := &cobra.Command{
		Use:   "run -- command [args...]",
		Short: "Run a command with secrets in environment",
		Long: `Execute a command with all stored secrets set as environment variables.
Usage:
  lb run -- sh -c 'echo $SECRET_VAR'
  lb run -- env | grep SECRET
  lb run -- ./my-app`,
		TraverseChildren: true,
		Run: func(cmd *cobra.Command, args []string) {
			// Check for remote flag
			remoteFlag, _ := cmd.Flags().GetString("remote")

			var secrets map[string]string
			var err error

			if remoteFlag != "" {
				// Fetch secrets from remote server
				secrets, err = fetchRemoteSecrets(remoteFlag)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			} else {
				// Get all secrets from local store
				store, encKey, err := getStoreAndKey()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				defer store.Close()

				keys, err := store.ListSecrets()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: failed to list secrets: %v\n", err)
					os.Exit(1)
				}

				secrets = make(map[string]string)
				for _, key := range keys {
					encrypted, err := store.GetSecret(key)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: failed to get secret '%s': %v\n", key, err)
						os.Exit(1)
					}

					// Decrypt the value
					decrypted, err := crypto.Decrypt(encrypted, encKey)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: failed to decrypt secret '%s': %v\n", key, err)
						os.Exit(1)
					}

					secrets[key] = string(decrypted)
				}
			}

			// Build environment with secrets
			env := os.Environ()
			for key, value := range secrets {
				env = append(env, fmt.Sprintf("%s=%s", key, value))
			}

			// Need at least one argument for the command
			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Error: no command provided\n")
				fmt.Fprintf(os.Stderr, "Usage: lb run -- command [args...]\n")
				os.Exit(1)
			}

			// Execute the command
			execCmd := exec.Command(args[0], args[1:]...)
			execCmd.Env = env
			execCmd.Stdin = os.Stdin
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr

			err = execCmd.Run()
			if err != nil {
				// Check if it's an exit error to get the exit code
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				fmt.Fprintf(os.Stderr, "Error: failed to execute command: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Add --remote flag to run command
	runCmd.Flags().StringP("remote", "r", "", "Remote server to fetch secrets from (e.g., localhost:8100)")

	// serve command - Start HTTP server
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server for remote access",
		Long: `Start an HTTP server to expose secrets for remote access.
Endpoints:
  GET /health - Returns {"status":"ok"}
  GET /secrets - Returns JSON array of all secret keys
  GET /secrets/:key - Returns decrypted secret value as plain text
  GET /env - Returns all secrets in export KEY="value" format`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			port, _ := cmd.Flags().GetString("port")

			// Get store and key once for all handlers
			store, encKey, err := getStoreAndKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			defer store.Close()

			// Health endpoint
			http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			})

			// Secrets list endpoint
			http.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
				keys, err := store.ListSecrets()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "Error: %v", err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(keys)
			})

			// Env endpoint - returns export format
			http.HandleFunc("/env", func(w http.ResponseWriter, r *http.Request) {
				keys, err := store.ListSecrets()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "Error: %v", err)
					return
				}

				w.Header().Set("Content-Type", "text/plain")

				for _, key := range keys {
					encrypted, err := store.GetSecret(key)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintf(w, "Error: %v", err)
						return
					}

					decrypted, err := crypto.Decrypt(encrypted, encKey)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintf(w, "Error: %v", err)
						return
					}

					value := string(decrypted)
					escapedValue := strings.NewReplacer(
						"\\", "\\\\",
						"\"", "\\\"",
						"$", "\\$",
						"`", "\\`",
					).Replace(value)

					fmt.Fprintf(w, "export %s=\"%s\"\n", key, escapedValue)
				}
			})

			// Secret get endpoint - handles /secrets/:key
			http.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
				key := strings.TrimPrefix(r.URL.Path, "/secrets/")
				if key == "" {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, "Error: no key specified")
					return
				}

				encrypted, err := store.GetSecret(key)
				if err != nil {
					if err == db.ErrNotFound {
						w.WriteHeader(http.StatusNotFound)
						fmt.Fprintf(w, "Error: secret '%s' not found", key)
						return
					}
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "Error: %v", err)
					return
				}

				decrypted, err := crypto.Decrypt(encrypted, encKey)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "Error: %v", err)
					return
				}

				w.Header().Set("Content-Type", "text/plain")
				w.Write(decrypted)
			})

			// Start server on localhost only
			addr := fmt.Sprintf("127.0.0.1:%s", port)
			fmt.Printf("✓ Server listening on http://%s\n", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				fmt.Fprintf(os.Stderr, "Error: server failed: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Add --port flag to serve command
	serveCmd.Flags().StringP("port", "p", "8100", "Port to listen on")

	// Modify env command to support --remote flag
	envCmdRun := envCmd.Run
	envCmd.Run = func(cmd *cobra.Command, args []string) {
		remoteFlag, _ := cmd.Flags().GetString("remote")

		if remoteFlag != "" {
			// Fetch from remote server
			url := fmt.Sprintf("http://%s/env", remoteFlag)
			resp, err := http.Get(url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to fetch from remote: %v\n", err)
				os.Exit(1)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				fmt.Fprintf(os.Stderr, "Error: remote server returned status %d: %s\n", resp.StatusCode, body)
				os.Exit(1)
			}

			// Print the response directly
			io.Copy(os.Stdout, resp.Body)
		} else {
			// Use original local implementation
			envCmdRun(cmd, args)
		}
	}

	// Add --remote flag to env command
	envCmd.Flags().StringP("remote", "r", "", "Remote server to fetch from (e.g., localhost:8100)")

	// Add commands to root
	rootCmd.AddCommand(initCmd, setCmd, getCmd, deleteCmd, listCmd, envCmd, runCmd, serveCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
