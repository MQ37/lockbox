package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// KeySize is the size of the AES-256 key in bytes
	KeySize = 32
	// NonceSize is the size of the GCM nonce in bytes
	NonceSize = 12
)

// GenerateKey generates a random 32-byte key suitable for AES-256 encryption.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// The returned ciphertext has the nonce prepended (first 12 bytes are the nonce).
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Validate key size
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", KeySize, len(key))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext that was encrypted using AES-256-GCM.
// The ciphertext is expected to have the nonce prepended (first 12 bytes).
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Validate key size
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", KeySize, len(key))
	}

	// Check minimum length (nonce + at least tag)
	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", NonceSize, len(ciphertext))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Extract nonce from beginning of ciphertext
	nonce := ciphertext[:NonceSize]
	actualCiphertext := ciphertext[NonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
