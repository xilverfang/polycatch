package apikey

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/polycatch/internal/config"
)

// APIKeyResponse represents the response from the API key creation endpoint
type APIKeyResponse struct {
	APIKey     string `json:"apiKey"`
	Secret     string `json:"secret"`
	Passphrase string `json:"passphrase"`
}

// CreateAPIKey creates API credentials using L1 authentication
func CreateAPIKey(ctx context.Context, cfg *config.Config) (*APIKeyResponse, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.SignerPrivateKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Derive signer address
	publicKey := crypto.PubkeyToAddress(privateKey.PublicKey)
	signerAddress := publicKey.Hex()

	// Get server timestamp first (required for L1 auth)
	timestamp, err := getServerTimestamp(ctx, cfg.CLOBAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get server timestamp: %w", err)
	}

	// Create EIP-712 signature
	signature, err := signL1AuthMessage(privateKey, signerAddress, timestamp, 0, int64(cfg.ChainID))
	if err != nil {
		return nil, fmt.Errorf("failed to sign L1 auth message: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// Try to derive existing API key first (GET /auth/derive-api-key)
	deriveURL := fmt.Sprintf("%s/auth/derive-api-key", cfg.CLOBAPIURL)
	deriveReq, err := http.NewRequestWithContext(ctx, "GET", deriveURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create derive request: %w", err)
	}

	// Set L1 authentication headers
	deriveReq.Header.Set("POLY_ADDRESS", signerAddress)
	deriveReq.Header.Set("POLY_SIGNATURE", signature)
	deriveReq.Header.Set("POLY_TIMESTAMP", timestamp)
	deriveReq.Header.Set("POLY_NONCE", "0")

	deriveResp, err := client.Do(deriveReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute derive request: %w", err)
	}
	defer deriveResp.Body.Close()

	deriveBody, err := io.ReadAll(deriveResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read derive response: %w", err)
	}

	// If derive succeeds, return the existing credentials
	if deriveResp.StatusCode == http.StatusOK {
		var apiKeyResp APIKeyResponse
		if err := json.Unmarshal(deriveBody, &apiKeyResp); err != nil {
			return nil, fmt.Errorf("failed to parse derive response: %w", err)
		}
		return &apiKeyResp, nil
	}

	// If derive fails (no existing key), create a new one
	// Need a fresh timestamp and signature for the create request
	timestamp, err = getServerTimestamp(ctx, cfg.CLOBAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get server timestamp for create: %w", err)
	}

	signature, err = signL1AuthMessage(privateKey, signerAddress, timestamp, 0, int64(cfg.ChainID))
	if err != nil {
		return nil, fmt.Errorf("failed to sign L1 auth message for create: %w", err)
	}

	createURL := fmt.Sprintf("%s/auth/api-key", cfg.CLOBAPIURL)
	createReq, err := http.NewRequestWithContext(ctx, "POST", createURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set L1 authentication headers
	createReq.Header.Set("POLY_ADDRESS", signerAddress)
	createReq.Header.Set("POLY_SIGNATURE", signature)
	createReq.Header.Set("POLY_TIMESTAMP", timestamp)
	createReq.Header.Set("POLY_NONCE", "0")

	createResp, err := client.Do(createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute create request: %w", err)
	}
	defer createResp.Body.Close()

	createBody, err := io.ReadAll(createResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read create response: %w", err)
	}

	if createResp.StatusCode != http.StatusOK && createResp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create API key failed with status %d: %s (derive response was: %s)",
			createResp.StatusCode, string(createBody), string(deriveBody))
	}

	// Parse response
	var apiKeyResp APIKeyResponse
	if err := json.Unmarshal(createBody, &apiKeyResp); err != nil {
		return nil, fmt.Errorf("failed to parse create response: %w", err)
	}

	return &apiKeyResp, nil
}

// getServerTimestamp fetches the current server timestamp from CLOB API
func getServerTimestamp(ctx context.Context, baseURL string) (string, error) {
	url := fmt.Sprintf("%s/time", baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read raw body first
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	bodyStr := strings.TrimSpace(string(bodyBytes))

	// Try parsing as raw number first (e.g., "1234567890")
	if _, err := fmt.Sscanf(bodyStr, "%d", new(int64)); err == nil {
		return bodyStr, nil
	}

	// Try parsing as JSON object with timestamp field
	var timeResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &timeResp); err != nil {
		return "", fmt.Errorf("failed to parse timestamp response: %w (body: %s)", err, bodyStr)
	}

	// Extract timestamp from response
	if ts, ok := timeResp["timestamp"]; ok {
		switch v := ts.(type) {
		case string:
			return v, nil
		case float64:
			return fmt.Sprintf("%.0f", v), nil
		}
	}

	return "", fmt.Errorf("timestamp not found in response: %s", bodyStr)
}

// signL1AuthMessage creates an EIP-712 signature for L1 authentication
func signL1AuthMessage(privateKey *ecdsa.PrivateKey, address string, timestamp string, nonce int, chainID int64) (string, error) {
	// EIP-712 Domain
	domainSeparator := encodeDomainSeparator("ClobAuthDomain", "1", big.NewInt(chainID))

	// ClobAuth struct hash
	clobAuthHash := encodeClobAuth(address, timestamp, big.NewInt(int64(nonce)))

	// Final hash: keccak256("\x19\x01" || domainSeparator || structHash)
	finalHash := crypto.Keccak256(
		[]byte("\x19\x01"),
		domainSeparator,
		clobAuthHash,
	)

	// Sign hash
	signature, err := crypto.Sign(finalHash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// Add recovery ID (v = 27 or 28)
	signature[64] += 27

	return hexutil.Encode(signature), nil
}

// encodeDomainSeparator encodes the EIP-712 domain separator
// Polymarket uses: name, version, chainId (no verifyingContract or salt)
func encodeDomainSeparator(name, version string, chainID *big.Int) []byte {
	// EIP712Domain type hash - Polymarket only uses name, version, chainId
	typeHash := crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId)"))

	// Encode domain values (each must be 32 bytes for ABI encoding)
	nameHash := crypto.Keccak256([]byte(name))
	versionHash := crypto.Keccak256([]byte(version))
	chainIDBytes := common.LeftPadBytes(chainID.Bytes(), 32)

	// Concatenate all parts
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, typeHash...)
	encoded = append(encoded, nameHash...)
	encoded = append(encoded, versionHash...)
	encoded = append(encoded, chainIDBytes...)

	// Domain separator hash
	return crypto.Keccak256(encoded)
}

// encodeClobAuth encodes the ClobAuth struct for EIP-712
func encodeClobAuth(address, timestamp string, nonce *big.Int) []byte {
	// ClobAuth type hash
	typeHash := crypto.Keccak256([]byte("ClobAuth(address address,string timestamp,uint256 nonce,string message)"))

	// Encode values - address must be padded to 32 bytes (left-padded)
	addr := common.HexToAddress(address)
	addressBytes := common.LeftPadBytes(addr.Bytes(), 32)

	// String values are hashed
	timestampHash := crypto.Keccak256([]byte(timestamp))

	// uint256 is 32 bytes
	nonceBytes := common.LeftPadBytes(nonce.Bytes(), 32)

	// Message hash
	messageHash := crypto.Keccak256([]byte("This message attests that I control the given wallet"))

	// Concatenate all parts
	encoded := make([]byte, 0, 160)
	encoded = append(encoded, typeHash...)
	encoded = append(encoded, addressBytes...)
	encoded = append(encoded, timestampHash...)
	encoded = append(encoded, nonceBytes...)
	encoded = append(encoded, messageHash...)

	// Struct hash
	return crypto.Keccak256(encoded)
}
