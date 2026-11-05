package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
			return nil, nil, fmt.Errorf("encryption key not found. Please run 'lockbox init' first")
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

func main() {
	rootCmd := &cobra.Command{
		Use:     "lockbox",
		Short:   "Lockbox - A secure secret management CLI",
		Long:    `Lockbox is a command-line tool for securely storing and managing secrets.`,
		Version: version,
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

	setCmd := newSetCmd()

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

	listCmd := newListCmd()

	// env command - Export secrets as environment variables
	envCmd := &cobra.Command{
		Use:   "env",
		Short: "Export secrets as environment variables",
		Long: `Export all stored secrets in shell export format.
Can be used with eval or source to set environment variables:
  eval $(lockbox env)
  source <(lockbox env)`,
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

	runCmd := newRunCmd()

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

	learnCmd := newLearnCmd()

	// Add commands to root
	rootCmd.AddCommand(initCmd, setCmd, getCmd, deleteCmd, listCmd, envCmd, runCmd, serveCmd, learnCmd,
		newHasCmd(), newCheckCmd(), newProfileCmd(), newHistoryCmd(), newRollbackCmd())

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
