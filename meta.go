package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/MQ37/lockbox/internal/crypto"
	"github.com/MQ37/lockbox/internal/db"
	"github.com/spf13/cobra"
)

// guardText refuses text that contains the value of any stored secret (8+
// bytes), or of the value about to be stored. Notes and tags are plaintext, so
// pasting a secret into one by mistake must fail.
func guardText(store *db.Store, encKey []byte, extraValue string, texts ...string) error {
	contains := func(v string) bool {
		if len(v) < minRedactLen {
			return false
		}
		for _, t := range texts {
			if strings.Contains(t, v) {
				return true
			}
		}
		return false
	}
	if contains(extraValue) {
		return fmt.Errorf("the note/tag contains the secret value being stored; notes are plaintext")
	}
	keys, err := store.ListSecrets()
	if err != nil {
		return err
	}
	for _, k := range keys {
		enc, err := store.GetSecret(k)
		if err != nil {
			return err
		}
		v, err := crypto.Decrypt(enc, encKey)
		if err != nil {
			continue
		}
		if contains(string(v)) {
			return fmt.Errorf("the note/tag contains the value of secret '%s'; notes and tags are plaintext", k)
		}
	}
	return nil
}

// applyMeta validates and stores a note and/or tags for an existing key.
func applyMeta(store *db.Store, encKey []byte, key string, note *string, tags []string, extraValue string) error {
	var texts []string
	if note != nil {
		if err := db.ValidateNote(*note); err != nil {
			return err
		}
		texts = append(texts, *note)
	}
	texts = append(texts, tags...)
	if len(texts) > 0 {
		if err := guardText(store, encKey, extraValue, texts...); err != nil {
			return err
		}
	}
	if note != nil {
		if err := store.SetNote(key, *note); err != nil {
			return err
		}
	}
	if len(tags) > 0 {
		if err := store.AddTags(key, tags); err != nil {
			return err
		}
	}
	return nil
}

func newNoteCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "note KEY [TEXT]",
		Short: "Show, set or clear the note of a secret",
		Long: `A note is one line (max 300 bytes) saying what a secret is for. It is stored
in PLAINTEXT and shown by "list -v" and "check", so never put a secret in it
(text containing any stored secret value is refused).

  lockbox note MAIN_WALLET_KEY "personal wallet, hex without 0x, for myapp tests"
  lockbox note MAIN_WALLET_KEY            # print it
  lockbox note MAIN_WALLET_KEY --clear`,
		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			clear, _ := cmd.Flags().GetBool("clear")
			store, encKey, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			key := args[0]
			if ok, err := store.HasSecret(key); err != nil {
				fatal("%v", err)
			} else if !ok {
				fatal("secret '%s' not found", key)
			}
			if clear && len(args) == 2 {
				fatal("use either TEXT or --clear")
			}
			if !clear && len(args) == 1 {
				m, err := store.AllMeta()
				if err != nil {
					fatal("%v", err)
				}
				if n := m[key].Note; n != "" {
					fmt.Println(n)
				}
				return
			}
			text := ""
			if !clear {
				text = args[1]
			}
			if err := applyMeta(store, encKey, key, &text, nil, ""); err != nil {
				fatal("%v", err)
			}
			if clear {
				fmt.Printf("✓ Note of '%s' cleared\n", key)
			} else {
				fmt.Printf("✓ Note of '%s' set\n", key)
			}
		},
	}
	c.Flags().Bool("clear", false, "remove the note")
	return c
}

func newTagCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "tag",
		Short: "Add, remove and list tags on secrets",
		Long: `Tags are short lowercase labels (a-z 0-9 _ . : -, max 64 characters, max 16
per key), stored in PLAINTEXT. A "key:value" form works well:
env:mainnet  env:testnet  kind:wallet-key  owner:personal  project:myapp

  lockbox tag add MAIN_WALLET_KEY env:mainnet kind:wallet-key
  lockbox tag rm  MAIN_WALLET_KEY env:mainnet
  lockbox tag list                  # every tag with its key count
  lockbox list --tag env:mainnet    # filter
  lockbox run --tag project:myapp -- cmd   # inject everything tagged`,
	}
	add := &cobra.Command{
		Use:   "add KEY TAG...",
		Short: "Add tags to a secret",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			tags, err := normTags(args[1:])
			if err != nil {
				fatal("%v", err)
			}
			if len(tags) == 0 {
				fatal("no tags given")
			}
			store, encKey, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			if err := applyMeta(store, encKey, args[0], nil, tags, ""); err != nil {
				if err == db.ErrNotFound {
					fatal("secret '%s' not found", args[0])
				}
				fatal("%v", err)
			}
			fmt.Printf("✓ Tagged '%s': %s\n", args[0], strings.Join(tags, " "))
		},
	}
	rm := &cobra.Command{
		Use:   "rm KEY TAG...",
		Short: "Remove tags from a secret",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			tags, err := normTags(args[1:])
			if err != nil {
				fatal("%v", err)
			}
			if len(tags) == 0 {
				fatal("no tags given")
			}
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			n, err := store.RemoveTags(args[0], tags)
			if err != nil {
				fatal("%v", err)
			}
			if n == 0 {
				fatal("'%s' had none of those tags", args[0])
			}
			fmt.Printf("✓ Removed %d tag(s) from '%s'\n", n, args[0])
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List all tags with how many secrets carry each",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			counts, err := store.TagCounts()
			if err != nil {
				fatal("%v", err)
			}
			names := make([]string, 0, len(counts))
			for t := range counts {
				names = append(names, t)
			}
			sort.Strings(names)
			for _, t := range names {
				fmt.Fprintf(os.Stdout, "%s\t%d\n", t, counts[t])
			}
		},
	}
	root.AddCommand(add, rm, list)
	return root
}
