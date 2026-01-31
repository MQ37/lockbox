package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	if len(key) != KeySize {
		t.Errorf("GenerateKey() returned key of size %d, want %d", len(key), KeySize)
	}

	// Generate another key and verify they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() second call failed: %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Error("GenerateKey() returned the same key twice, keys should be random")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	plaintext := []byte("Hello, this is a secret message!")

	// Encrypt
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Verify ciphertext is not empty
	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}

	// Verify ciphertext contains nonce and encrypted data
	if len(ciphertext) < NonceSize {
		t.Errorf("Encrypt() returned ciphertext shorter than nonce size: %d < %d", len(ciphertext), NonceSize)
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Verify plaintext matches
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() returned %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	plaintext := []byte{}

	// Encrypt empty plaintext
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() failed on empty plaintext: %v", err)
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Verify plaintext matches
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() returned %q, want empty slice", decrypted)
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	plaintext := []byte("test")
	invalidKey := []byte("short")

	_, err := Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Error("Encrypt() with invalid key size should return error")
	}
}

func TestDecryptInvalidKeySize(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("test")
	ciphertext, _ := Encrypt(plaintext, key)

	invalidKey := []byte("short")
	_, err := Decrypt(ciphertext, invalidKey)
	if err == nil {
		t.Error("Decrypt() with invalid key size should return error")
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key, _ := GenerateKey()

	// Ciphertext too short (less than nonce size)
	_, err := Decrypt([]byte("short"), key)
	if err == nil {
		t.Error("Decrypt() with ciphertext shorter than nonce should return error")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	plaintext := []byte("secret message")
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Tamper with the ciphertext (after nonce)
	if len(ciphertext) > NonceSize {
		ciphertext[NonceSize] ^= 0xFF
	}

	_, err = Decrypt(ciphertext, key)
	if err == nil {
		t.Error("Decrypt() with tampered ciphertext should return error")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	plaintext := []byte("secret")
	ciphertext, _ := Encrypt(plaintext, key1)

	// Try to decrypt with wrong key
	_, err := Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("Decrypt() with wrong key should return error")
	}
}

func TestLargeData(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	// Create a large plaintext
	plaintext := make([]byte, 10*1024*1024) // 10 MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	// Encrypt
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() failed on large data: %v", err)
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypt() returned different data for large plaintext")
	}
}
