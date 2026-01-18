package storage

import "errors"

// Validation errors
var (
	ErrMissingSignerKey     = errors.New("signer private key is required")
	ErrMissingFunderAddress = errors.New("funder address is required")
	ErrMissingAPIKey        = errors.New("API key is required")
	ErrMissingAPISecret     = errors.New("API secret is required")
	ErrMissingAPIPassphrase = errors.New("API passphrase is required")
)

// Database errors
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserExists        = errors.New("user already exists")
	ErrTradeNotFound     = errors.New("trade not found")
	ErrDatabaseClosed    = errors.New("database connection closed")
	ErrInvalidTelegramID = errors.New("invalid telegram ID")
)

// Authentication errors
var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrSessionExpired  = errors.New("session expired")
	ErrAccountLocked   = errors.New("account locked due to too many failed attempts")
	ErrAccountInactive = errors.New("account is inactive")
)
