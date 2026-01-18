package crypto

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestEncryptDecrypt tests basic encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"medium", []byte("The quick brown fox jumps over the lazy dog")},
		{"with_nulls", []byte("hello\x00world\x00test")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}},
		{"unicode", []byte("Hello, 世界! 🔐")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := Encrypt(tc.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := Decrypt(ciphertext, key)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("Decrypted data doesn't match original\ngot: %v\nwant: %v", decrypted, tc.plaintext)
			}
		})
	}
}

// TestEncryptDifferentCiphertext verifies each encryption produces different ciphertext
func TestEncryptDifferentCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("test message")

	ciphertext1, _ := Encrypt(plaintext, key)
	ciphertext2, _ := Encrypt(plaintext, key)

	if ciphertext1 == ciphertext2 {
		t.Error("Same plaintext should produce different ciphertext (random nonce)")
	}
}

// TestDecryptWrongKey verifies decryption fails with wrong key
func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	plaintext := []byte("secret message")
	ciphertext, _ := Encrypt(plaintext, key1)

	_, err := Decrypt(ciphertext, key2)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got: %v", err)
	}
}

// TestDecryptTamperedData verifies decryption fails if data is tampered
func TestDecryptTamperedData(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("secret message")
	ciphertext, _ := Encrypt(plaintext, key)

	// Tamper with the ciphertext
	tampered := []byte(ciphertext)
	if len(tampered) > 20 {
		tampered[20] ^= 0xff // Flip some bits
	}

	_, err := Decrypt(string(tampered), key)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed for tampered data, got: %v", err)
	}
}

// TestEncryptInvalidKey verifies encryption fails with invalid key size
func TestEncryptInvalidKey(t *testing.T) {
	testCases := []struct {
		name    string
		keySize int
	}{
		{"too_short", 16},
		{"too_long", 64},
		{"empty", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			_, err := Encrypt([]byte("test"), key)
			if err != ErrInvalidKeySize {
				t.Errorf("Expected ErrInvalidKeySize for %d-byte key, got: %v", tc.keySize, err)
			}
		})
	}
}

// TestEncryptWithAAD tests encryption with additional authenticated data
func TestEncryptWithAAD(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("secret message")
	aad := []byte("user_id:12345")

	ciphertext, err := EncryptWithAAD(plaintext, key, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := DecryptWithAAD(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("DecryptWithAAD failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data doesn't match original")
	}

	// Decrypt with wrong AAD should fail
	wrongAAD := []byte("user_id:99999")
	_, err = DecryptWithAAD(ciphertext, key, wrongAAD)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed with wrong AAD, got: %v", err)
	}
}

// TestDeriveKey tests key derivation from password
func TestDeriveKey(t *testing.T) {
	password := "MySecurePassword123!"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	key1, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != KeySize {
		t.Errorf("Derived key has wrong size: got %d, want %d", len(key1), KeySize)
	}

	// Same password and salt should produce same key
	key2, _ := DeriveKey(password, salt)
	if !bytes.Equal(key1, key2) {
		t.Error("Same password+salt should produce same key")
	}

	// Different salt should produce different key
	salt2, _ := GenerateSalt()
	key3, _ := DeriveKey(password, salt2)
	if bytes.Equal(key1, key3) {
		t.Error("Different salt should produce different key")
	}

	// Different password should produce different key
	key4, _ := DeriveKey("DifferentPassword123", salt)
	if bytes.Equal(key1, key4) {
		t.Error("Different password should produce different key")
	}
}

// TestDeriveKeyPasswordTooShort tests minimum password length enforcement
func TestDeriveKeyPasswordTooShort(t *testing.T) {
	salt, _ := GenerateSalt()

	_, err := DeriveKey("short", salt)
	if err != ErrPasswordTooShort {
		t.Errorf("Expected ErrPasswordTooShort, got: %v", err)
	}

	_, err = DeriveKey("11character", salt) // exactly 11 chars
	if err != ErrPasswordTooShort {
		t.Errorf("Expected ErrPasswordTooShort for 11-char password, got: %v", err)
	}

	// 12 characters should work
	_, err = DeriveKey("12characters!", salt)
	if err != nil {
		t.Errorf("12-char password should work, got: %v", err)
	}
}

// TestHashPassword tests password hashing
func TestHashPassword(t *testing.T) {
	password := "MySecurePassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Hash should start with $argon2id$
	if hash[:9] != "$argon2id" {
		t.Errorf("Hash should start with $argon2id, got: %s", hash[:20])
	}

	// Same password should produce different hashes (random salt)
	hash2, _ := HashPassword(password)
	if hash == hash2 {
		t.Error("Same password should produce different hashes (random salt)")
	}
}

// TestVerifyPassword tests password verification
func TestVerifyPassword(t *testing.T) {
	password := "MySecurePassword123!"
	hash, _ := HashPassword(password)

	// Correct password should verify
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Error("Correct password should verify")
	}

	// Wrong password should not verify
	valid, err = VerifyPassword("WrongPassword123!", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

// TestCheckPasswordStrength tests password strength checking
func TestCheckPasswordStrength(t *testing.T) {
	testCases := []struct {
		password string
		expected PasswordStrength
	}{
		{"short", PasswordWeak},
		{"onlylowercase12", PasswordFair},
		{"MixedCase123456", PasswordFair},
		{"MixedCase123456!", PasswordStrong},
		{"VeryLongPasswordWith123!", PasswordExcellent},
	}

	for _, tc := range testCases {
		t.Run(tc.password, func(t *testing.T) {
			strength, _ := CheckPasswordStrength(tc.password)
			if strength != tc.expected {
				t.Errorf("Password %q: expected strength %d, got %d", tc.password, tc.expected, strength)
			}
		})
	}
}

// TestSecureBuffer tests secure buffer operations
func TestSecureBuffer(t *testing.T) {
	sb := NewSecureBuffer(100)

	data := []byte("secret data")
	sb.Write(data)

	// Read data
	if !bytes.Equal(sb.Bytes(), data) {
		t.Error("Buffer content doesn't match")
	}

	// Close should zero the data
	sb.Close()

	if sb.Bytes() != nil {
		t.Error("Buffer should be nil after close")
	}
}

// TestSecureBufferFromBytes tests creating buffer from existing bytes
func TestSecureBufferFromBytes(t *testing.T) {
	original := []byte("secret data")
	sb := NewSecureBufferFromBytes(original)

	// Data should be copied
	if !bytes.Equal(sb.Bytes(), original) {
		t.Error("Buffer content doesn't match")
	}

	// Modifying original should not affect buffer
	original[0] = 'X'
	if sb.Bytes()[0] == 'X' {
		t.Error("Buffer should be independent of original")
	}

	sb.Close()
}

// TestSecureZero tests memory zeroing
func TestSecureZero(t *testing.T) {
	data := []byte("secret data that should be zeroed")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZero(data)

	// All bytes should be zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %d", i, b)
		}
	}
}

// TestSecureSession tests session management
func TestSecureSession(t *testing.T) {
	expired := false
	session := NewSecureSession(100*time.Millisecond, func() {
		expired = true
	})

	// Session should be valid initially
	if !session.IsValid() {
		t.Error("New session should be valid")
	}

	// Set credentials
	creds := []byte(`{"key": "secret"}`)
	session.SetCredentials(creds)

	// Should be able to get credentials
	if !bytes.Equal(session.GetCredentials(), creds) {
		t.Error("Credentials don't match")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Session should be expired
	if session.IsValid() {
		t.Error("Session should be expired")
	}

	// Credentials should be nil
	if session.GetCredentials() != nil {
		t.Error("Credentials should be nil after expiration")
	}

	// Callback should have been called
	time.Sleep(10 * time.Millisecond) // Give callback goroutine time to run
	if !expired {
		t.Error("Expiration callback should have been called")
	}
}

// TestSessionManager tests session manager
func TestSessionManager(t *testing.T) {
	sm := NewSessionManager(100 * time.Millisecond)

	// Create session for user
	userID := int64(12345)
	session := sm.CreateSession(userID)

	if session == nil {
		t.Fatal("CreateSession should return session")
	}

	// Get session
	retrieved := sm.GetSession(userID)
	if retrieved != session {
		t.Error("GetSession should return same session")
	}

	// Non-existent user
	if sm.GetSession(99999) != nil {
		t.Error("GetSession for non-existent user should return nil")
	}

	// Active sessions count
	if sm.ActiveSessions() != 1 {
		t.Errorf("Expected 1 active session, got %d", sm.ActiveSessions())
	}

	// Expire session
	sm.ExpireSession(userID)
	if sm.GetSession(userID) != nil {
		t.Error("Expired session should not be retrievable")
	}
}

// TestFullEncryptionFlow tests a complete encryption workflow
func TestFullEncryptionFlow(t *testing.T) {
	// Simulate user credentials
	type Credentials struct {
		PrivateKey string `json:"private_key"`
		APIKey     string `json:"api_key"`
		APISecret  string `json:"api_secret"`
	}

	creds := Credentials{
		PrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		APIKey:     "550e8400-e29b-41d4-a716-446655440000",
		APISecret:  "base64SecretKey==",
	}

	// User provides password
	password := "MySecurePassword123!"

	// Generate salt (store this with the user record)
	salt, _ := GenerateSalt()

	// Derive encryption key from password
	key, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// Serialize credentials to JSON
	plaintext, _ := json.Marshal(creds)

	// Encrypt credentials (store this with the user record)
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Clear the key from memory (in real code, use SecureZero)
	SecureZero(key)

	// --- Later, when user unlocks ---

	// Derive key again from password
	key2, _ := DeriveKey(password, salt)

	// Decrypt credentials
	decrypted, err := Decrypt(ciphertext, key2)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Parse credentials
	var retrievedCreds Credentials
	if err := json.Unmarshal(decrypted, &retrievedCreds); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	// Verify
	if retrievedCreds.PrivateKey != creds.PrivateKey {
		t.Error("PrivateKey doesn't match")
	}
	if retrievedCreds.APIKey != creds.APIKey {
		t.Error("APIKey doesn't match")
	}
	if retrievedCreds.APISecret != creds.APISecret {
		t.Error("APISecret doesn't match")
	}

	// Clean up
	SecureZero(key2)
	SecureZero(decrypted)
}

// BenchmarkDeriveKey benchmarks key derivation performance
func BenchmarkDeriveKey(b *testing.B) {
	password := "MySecurePassword123!"
	salt, _ := GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKey(password, salt)
	}
}

// BenchmarkEncrypt benchmarks encryption performance
func BenchmarkEncrypt(b *testing.B) {
	key, _ := GenerateKey()
	plaintext := make([]byte, 1024) // 1 KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(plaintext, key)
	}
}

// BenchmarkDecrypt benchmarks decryption performance
func BenchmarkDecrypt(b *testing.B) {
	key, _ := GenerateKey()
	plaintext := make([]byte, 1024)
	ciphertext, _ := Encrypt(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(ciphertext, key)
	}
}
