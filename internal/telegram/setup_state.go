package telegram

import (
	"bytes"

	"github.com/polywatch/internal/crypto"
)

func secureBufferFromString(value string) *crypto.SecureBuffer {
	if value == "" {
		return nil
	}
	raw := []byte(value)
	buf := crypto.NewSecureBufferFromBytes(raw)
	crypto.SecureZero(raw)
	return buf
}

func secureBufferToString(buf *crypto.SecureBuffer) string {
	if buf == nil {
		return ""
	}
	return string(buf.Bytes())
}

func (s *SetupState) SetPassword(value string) {
	if s.Password != nil {
		s.Password.Close()
	}
	s.Password = secureBufferFromString(value)
}

func (s *SetupState) SetPrivateKey(value string) {
	if s.PrivateKey != nil {
		s.PrivateKey.Close()
	}
	s.PrivateKey = secureBufferFromString(value)
}

func (s *SetupState) SetAPIKey(value string) {
	if s.APIKey != nil {
		s.APIKey.Close()
	}
	s.APIKey = secureBufferFromString(value)
}

func (s *SetupState) SetAPISecret(value string) {
	if s.APISecret != nil {
		s.APISecret.Close()
	}
	s.APISecret = secureBufferFromString(value)
}

func (s *SetupState) SetAPIPassphrase(value string) {
	if s.APIPassphrase != nil {
		s.APIPassphrase.Close()
	}
	s.APIPassphrase = secureBufferFromString(value)
}

func (s *SetupState) PasswordMatches(confirm string) bool {
	if s.Password == nil {
		return false
	}
	return bytes.Equal(s.Password.Bytes(), []byte(confirm))
}

func (s *SetupState) PasswordString() string {
	return secureBufferToString(s.Password)
}

func (s *SetupState) PrivateKeyString() string {
	return secureBufferToString(s.PrivateKey)
}

func (s *SetupState) APIKeyString() string {
	return secureBufferToString(s.APIKey)
}

func (s *SetupState) APISecretString() string {
	return secureBufferToString(s.APISecret)
}

func (s *SetupState) APIPassphraseString() string {
	return secureBufferToString(s.APIPassphrase)
}

func (s *SetupState) ClearSensitive() {
	if s.Password != nil {
		s.Password.Close()
		s.Password = nil
	}
	if s.PrivateKey != nil {
		s.PrivateKey.Close()
		s.PrivateKey = nil
	}
	if s.APIKey != nil {
		s.APIKey.Close()
		s.APIKey = nil
	}
	if s.APISecret != nil {
		s.APISecret.Close()
		s.APISecret = nil
	}
	if s.APIPassphrase != nil {
		s.APIPassphrase.Close()
		s.APIPassphrase = nil
	}
}
