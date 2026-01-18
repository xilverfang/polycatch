// Package crypto provides cryptographic utilities for secure data handling.
// Implements AES-256-GCM encryption with industry-standard security practices.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Security constants
const (
	// AES-256 requires 32-byte keys
	KeySize = 32

	// GCM standard nonce size (96 bits / 12 bytes)
	NonceSize = 12

	// GCM authentication tag size (128 bits / 16 bytes)
	TagSize = 16
)

// Encryption errors - generic messages to prevent information leakage
var (
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrInvalidData      = errors.New("invalid data")
)

// EncryptedData represents the components of encrypted data
type EncryptedData struct {
	Nonce      []byte // 12 bytes - unique per encryption
	Ciphertext []byte // Variable length - includes auth tag
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// The key must be exactly 32 bytes (use DeriveKey to generate from password).
// Returns base64-encoded ciphertext with prepended nonce.
//
// Security properties:
// - Authenticated encryption (confidentiality + integrity)
// - Random 96-bit nonce (safe for up to 2^32 encryptions per key)
// - 128-bit authentication tag
func Encrypt(plaintext []byte, key []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrInvalidKeySize
	}

	if plaintext == nil {
		return "", ErrInvalidData
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	// Generate cryptographically secure random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrEncryptionFailed
	}

	// Encrypt and authenticate
	// Seal appends the ciphertext to nonce, so result is: nonce || ciphertext || tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Encode as base64 for safe storage/transmission
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// EncryptWithAAD encrypts plaintext with Additional Authenticated Data.
// AAD is authenticated but not encrypted - useful for binding ciphertext to context.
// Example: Use telegram_id as AAD to prevent ciphertext from being used for another user.
func EncryptWithAAD(plaintext []byte, key []byte, aad []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrInvalidKeySize
	}

	if plaintext == nil {
		return "", ErrInvalidData
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrEncryptionFailed
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrEncryptionFailed
	}

	// Seal with AAD - AAD is authenticated but not encrypted
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM.
// Returns the original plaintext or an error if decryption/authentication fails.
//
// Security properties:
// - Verifies authentication tag before returning plaintext
// - Constant-time comparison prevents timing attacks
// - Generic error message prevents oracle attacks
func Decrypt(ciphertextB64 string, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if ciphertextB64 == "" {
		return nil, ErrInvalidData
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Minimum size: nonce + tag (empty plaintext is valid)
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrDecryptionFailed
	}

	// Extract nonce (first 12 bytes)
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Don't reveal specific error - prevents padding oracle attacks
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptWithAAD decrypts ciphertext that was encrypted with AAD.
// The same AAD must be provided for successful decryption.
func DecryptWithAAD(ciphertextB64 string, key []byte, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	if ciphertextB64 == "" {
		return nil, ErrInvalidData
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrDecryptionFailed
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	// Decrypt with AAD verification
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKey generates a cryptographically secure random 256-bit key.
// Use this for symmetric encryption keys, not for password-derived keys.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// GenerateSalt generates a cryptographically secure random salt.
// Salt should be at least 16 bytes (128 bits) per OWASP recommendations.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32) // 256 bits for extra security margin
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// ConstantTimeCompare performs constant-time comparison of two byte slices.
// Returns true if slices are equal, false otherwise.
// Prevents timing attacks when comparing secrets.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
