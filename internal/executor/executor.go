package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	// Official Polymarket order signing library
	"github.com/polymarket/go-order-utils/pkg/builder"
	"github.com/polymarket/go-order-utils/pkg/model"

	"github.com/polycatch/internal/cache"
	"github.com/polycatch/internal/config"
	"github.com/polycatch/internal/ipc"
	"github.com/polycatch/internal/types"
	"github.com/polycatch/internal/utils"
)

type polymarketErrorResponse struct {
	Error   *string `json:"error"`
	Message *string `json:"message"`
	Code    *string `json:"code"`
}

type polymarketErrorEnvelope struct {
	Error polymarketErrorResponse `json:"error"`
}

const erc20AllowanceABIJSON = `[
  {"constant":true,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"type":"function"},
  {"constant":false,"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"}
]`

const erc1155ApprovalABIJSON = `[
  {"constant":true,"inputs":[{"name":"owner","type":"address"},{"name":"operator","type":"address"}],"name":"isApprovedForAll","outputs":[{"name":"","type":"bool"}],"type":"function"},
  {"constant":false,"inputs":[{"name":"operator","type":"address"},{"name":"approved","type":"bool"}],"name":"setApprovalForAll","outputs":[],"type":"function"}
]`

const safeOwnersABIJSON = `[
  {"constant":true,"inputs":[],"name":"getOwners","outputs":[{"name":"","type":"address[]"}],"type":"function"}
]`

const proxyFactoryABIJSON = `[
  {"inputs":[{"components":[{"name":"typeCode","type":"uint8"},{"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"}],"name":"calls","type":"tuple[]"}],"name":"proxy","outputs":[{"name":"returnValues","type":"bytes[]"}],"stateMutability":"payable","type":"function"}
]`

const multiSendABIJSON = `[
  {"inputs":[{"internalType":"bytes","name":"transactions","type":"bytes"}],"name":"multiSend","outputs":[],"stateMutability":"nonpayable","type":"function"}
]`

var (
	erc20AllowanceABI     abi.ABI
	erc20AllowanceOnce    sync.Once
	erc20AllowanceABIErr  error
	erc1155ApprovalABI    abi.ABI
	erc1155ApprovalOnce   sync.Once
	erc1155ApprovalABIErr error
	safeOwnersABI         abi.ABI
	safeOwnersOnce        sync.Once
	safeOwnersABIErr      error
	proxyFactoryABI       abi.ABI
	proxyFactoryOnce      sync.Once
	proxyFactoryABIErr    error
	multiSendABI          abi.ABI
	multiSendOnce         sync.Once
	multiSendABIErr       error
)

func getERC20AllowanceABI() (abi.ABI, error) {
	erc20AllowanceOnce.Do(func() {
		erc20AllowanceABI, erc20AllowanceABIErr = abi.JSON(strings.NewReader(erc20AllowanceABIJSON))
	})
	return erc20AllowanceABI, erc20AllowanceABIErr
}

func getERC1155ApprovalABI() (abi.ABI, error) {
	erc1155ApprovalOnce.Do(func() {
		erc1155ApprovalABI, erc1155ApprovalABIErr = abi.JSON(strings.NewReader(erc1155ApprovalABIJSON))
	})
	return erc1155ApprovalABI, erc1155ApprovalABIErr
}

func getSafeOwnersABI() (abi.ABI, error) {
	safeOwnersOnce.Do(func() {
		safeOwnersABI, safeOwnersABIErr = abi.JSON(strings.NewReader(safeOwnersABIJSON))
	})
	return safeOwnersABI, safeOwnersABIErr
}

func getProxyFactoryABI() (abi.ABI, error) {
	proxyFactoryOnce.Do(func() {
		proxyFactoryABI, proxyFactoryABIErr = abi.JSON(strings.NewReader(proxyFactoryABIJSON))
	})
	return proxyFactoryABI, proxyFactoryABIErr
}

func getMultiSendABI() (abi.ABI, error) {
	multiSendOnce.Do(func() {
		multiSendABI, multiSendABIErr = abi.JSON(strings.NewReader(multiSendABIJSON))
	})
	return multiSendABI, multiSendABIErr
}

func truncateForLog(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

func sanitizeOrderPayloadForLog(payload []byte) string {
	// Payload includes signatures; never log them in full.
	// This is best-effort and intentionally minimal (error-path only).
	s := string(payload)
	s = redactJSONStringField(s, `"signature"`)
	return s
}

func redactJSONStringField(s string, fieldWithQuotes string) string {
	// Redacts a JSON string field like: "signature":"...".
	// fieldWithQuotes should include the surrounding quotes, e.g. `"signature"`.
	idx := strings.Index(s, fieldWithQuotes)
	if idx < 0 {
		return s
	}
	// Find the ':' after the field.
	colon := strings.IndexByte(s[idx+len(fieldWithQuotes):], ':')
	if colon < 0 {
		return s
	}
	colonIdx := idx + len(fieldWithQuotes) + colon
	// Find the first quote of the value.
	firstQuote := strings.IndexByte(s[colonIdx:], '"')
	if firstQuote < 0 {
		return s
	}
	start := colonIdx + firstQuote
	// Find the ending quote of the value, naive scan (handles typical compact JSON).
	end := start + 1
	for end < len(s) {
		if s[end] == '"' && s[end-1] != '\\' {
			break
		}
		end++
	}
	if end >= len(s) {
		return s
	}
	return s[:start+1] + "***REDACTED***" + s[end:]
}

func extractPolymarketRequestIDs(h http.Header) map[string]string {
	ids := map[string]string{}
	candidates := []string{
		"X-Request-Id",
		"X-Request-ID",
		"X-Amzn-Trace-Id",
		"CF-Ray",
		"Cf-Ray",
	}
	for _, k := range candidates {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			ids[k] = v
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}

func formatPolymarketAPIErrorBody(body []byte) string {
	b := strings.TrimSpace(string(body))
	if b == "" {
		return ""
	}

	// Best-effort parse for common error shapes.
	var env polymarketErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil {
		parts := make([]string, 0, 3)
		if env.Error.Code != nil && strings.TrimSpace(*env.Error.Code) != "" {
			parts = append(parts, fmt.Sprintf("code=%s", *env.Error.Code))
		}
		if env.Error.Message != nil && strings.TrimSpace(*env.Error.Message) != "" {
			parts = append(parts, fmt.Sprintf("message=%s", *env.Error.Message))
		}
		if env.Error.Error != nil && strings.TrimSpace(*env.Error.Error) != "" {
			parts = append(parts, fmt.Sprintf("error=%s", *env.Error.Error))
		}
		if len(parts) > 0 {
			return strings.Join(parts, " | ")
		}
	}

	// Some endpoints return { "error": "...", "message": "...", "code": "..." }
	var flat polymarketErrorResponse
	if err := json.Unmarshal(body, &flat); err == nil {
		parts := make([]string, 0, 3)
		if flat.Code != nil && strings.TrimSpace(*flat.Code) != "" {
			parts = append(parts, fmt.Sprintf("code=%s", *flat.Code))
		}
		if flat.Message != nil && strings.TrimSpace(*flat.Message) != "" {
			parts = append(parts, fmt.Sprintf("message=%s", *flat.Message))
		}
		if flat.Error != nil && strings.TrimSpace(*flat.Error) != "" {
			parts = append(parts, fmt.Sprintf("error=%s", *flat.Error))
		}
		if len(parts) > 0 {
			return strings.Join(parts, " | ")
		}
	}

	// Fallback: return a truncated preview, but still include the raw body (it shouldn't contain secrets).
	return truncateForLog(b, 2000)
}

func looksLikeCloudflareBlock(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if strings.Contains(ct, "text/html") {
		// Cloudflare blocks are HTML pages. We look for common markers.
		b := strings.ToLower(string(body))
		return strings.Contains(b, "cloudflare") && (strings.Contains(b, "you have been blocked") || strings.Contains(b, "cf-error-details"))
	}
	return false
}

const (
	relayerStateConfirmed = "STATE_CONFIRMED"
	relayerStateFailed    = "STATE_FAILED"
	relayerStateInvalid   = "STATE_INVALID"
)

type relayerNonceResponse struct {
	Nonce string `json:"nonce"`
}

type relayerRelayPayloadResponse struct {
	Address string `json:"address"`
	Nonce   string `json:"nonce"`
}

type relayerSubmitResponse struct {
	TransactionID   string `json:"transactionID"`
	State           string `json:"state"`
	TransactionHash string `json:"transactionHash"`
	Hash            string `json:"hash"`
}

type relayerTransaction struct {
	TransactionID   string  `json:"transactionId"`
	State           string  `json:"state"`
	TransactionHash *string `json:"transactionHash"`
	Hash            *string `json:"hash"`
}

type relayerSafeSignatureParams struct {
	GasPrice       string `json:"gasPrice"`
	Operation      string `json:"operation"`
	SafeTxnGas     string `json:"safeTxnGas"`
	BaseGas        string `json:"baseGas"`
	GasToken       string `json:"gasToken"`
	RefundReceiver string `json:"refundReceiver"`
}

type relayerProxySignatureParams struct {
	GasPrice   string `json:"gasPrice"`
	GasLimit   string `json:"gasLimit"`
	RelayerFee string `json:"relayerFee"`
	RelayHub   string `json:"relayHub"`
	Relay      string `json:"relay"`
}

type relayerTransactionRequest struct {
	Type            string      `json:"type"`
	From            string      `json:"from"`
	To              string      `json:"to"`
	ProxyWallet     string      `json:"proxyWallet,omitempty"`
	Data            string      `json:"data"`
	Nonce           string      `json:"nonce,omitempty"`
	Signature       string      `json:"signature"`
	SignatureParams interface{} `json:"signatureParams"`
	Metadata        string      `json:"metadata,omitempty"`
}

// generateRandomSalt generates a random salt within 2^32 range
// This matches Polymarket's official go-order-utils library
// Using nanosecond timestamps would exceed JavaScript's safe integer limit
func generateRandomSalt() int64 {
	maxInt := int64(math.Pow(2, 32))
	nBig, err := cryptorand.Int(cryptorand.Reader, big.NewInt(maxInt))
	if err != nil {
		// Fallback to millisecond timestamp if crypto/rand fails (very unlikely)
		return time.Now().UnixMilli() % maxInt
	}
	return nBig.Int64()
}

// redactForLog masks sensitive values to prevent accidental leakage in logs.
// Keeps a small prefix/suffix for troubleshooting without exposing full secrets.
func redactForLog(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// Executor executes trades based on trade signals from the Analyst
type Executor struct {
	config         *config.Config
	client         *ethclient.Client
	tradeSignalsCh <-chan *types.TradeSignal
	errorsCh       chan error
	stopCh         chan struct{}
	running        bool
	httpClient     *http.Client
	ipcReader      *ipc.Reader                       // IPC reader for receiving signals from monitor
	useIPC         bool                              // Whether to use IPC instead of channel
	signerAddress  string                            // Signer address derived from private key
	privateKey     *ecdsa.PrivateKey                 // Parsed private key for signing
	orderBuilder   *builder.ExchangeOrderBuilderImpl // Official Polymarket order builder
	tokenCache     *cache.TokenCache                 // Cache for token metadata (tick size, fee rate, etc.)
	priceCache     *cache.PriceCache                 // Cache for current prices (short TTL)
}

// GetUSDCBalanceOnChain returns the funder address' on-chain USDC balance (raw units, 6 decimals).
// This uses an eth_call to the ERC20 balanceOf function.
func (e *Executor) GetUSDCBalanceOnChain(ctx context.Context) (*big.Int, error) {
	// Connect to Polygon if not already connected
	if e.client == nil {
		if e.config.PolygonWSSURL == "" {
			return nil, fmt.Errorf("POLYGON_WSS_URL is empty; cannot fetch on-chain balance")
		}
		client, err := ethclient.DialContext(ctx, strings.Replace(e.config.PolygonWSSURL, "wss://", "https://", 1))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Polygon: %w", err)
		}
		e.client = client
	}

	if strings.TrimSpace(e.config.USDCContract) == "" {
		return nil, fmt.Errorf("USDCContract is empty; cannot fetch on-chain balance")
	}
	if strings.TrimSpace(e.config.FunderAddress) == "" {
		return nil, fmt.Errorf("FunderAddress is empty; cannot fetch on-chain balance")
	}

	usdcContract := common.HexToAddress(e.config.USDCContract)
	funderAddr := common.HexToAddress(e.config.FunderAddress)

	// ERC20 balanceOf(address) function signature
	// balanceOf(address) = 0x70a08231
	balanceOfSig := common.Hex2Bytes("70a08231")
	addressParam := common.LeftPadBytes(funderAddr.Bytes(), 32)
	balanceOfData := append(balanceOfSig, addressParam...)

	result, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &usdcContract,
		Data: balanceOfData,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get USDC balance: %w", err)
	}

	return new(big.Int).SetBytes(result), nil
}

// New creates a new Executor instance
func New(cfg *config.Config) (*Executor, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	// Validate executor-specific requirements
	if cfg.FunderAddress == "" {
		return nil, errors.New("FUNDER_ADDRESS is required for executor")
	}
	if cfg.SignerPrivateKey == "" {
		return nil, errors.New("SIGNER_PRIVATE_KEY is required for executor")
	}

	// Validate CLOB API credentials (L2 auth)
	if strings.TrimSpace(cfg.CLOBAPIKey) == "" {
		return nil, errors.New("CLOB_API_KEY is required and cannot be empty")
	}
	if strings.TrimSpace(cfg.CLOBAPISecret) == "" {
		return nil, errors.New("CLOB_API_SECRET is required and cannot be empty")
	}
	if strings.TrimSpace(cfg.CLOBAPIPassphrase) == "" {
		return nil, errors.New("CLOB_API_PASSPHRASE is required and cannot be empty")
	}

	// Builder API credentials are required only when submitting relayer approvals.

	// Derive signer address from private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.SignerPrivateKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	publicKey := crypto.PubkeyToAddress(privateKey.PublicKey)
	signerAddress := publicKey.Hex()

	// Initialize the official Polymarket order builder
	// ChainID 137 = Polygon mainnet
	orderBuilder := builder.NewExchangeOrderBuilderImpl(
		big.NewInt(cfg.ChainID),
		nil, // Use default salt generator from the library
	)

	// Log credential status (without exposing values)
	log.Printf("Executor | CLOB API credentials loaded: Key=%d chars, Secret=%d chars, Passphrase=%d chars",
		len(strings.TrimSpace(cfg.CLOBAPIKey)),
		len(strings.TrimSpace(cfg.CLOBAPISecret)),
		len(strings.TrimSpace(cfg.CLOBAPIPassphrase)))
	log.Printf("Executor | Using official Polymarket go-order-utils library for signing")
	log.Printf("Executor | Signer address: %s", signerAddress)

	// Create HTTP client with connection reuse
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Initialize IPC reader for receiving signals from monitor via Unix socket
	socketPath := ipc.GetDefaultSocketPath()
	ipcReader := ipc.NewReader(socketPath)

	return &Executor{
		config:        cfg,
		errorsCh:      make(chan error, 10),
		stopCh:        make(chan struct{}),
		running:       false,
		httpClient:    httpClient,
		ipcReader:     ipcReader,
		useIPC:        false,
		signerAddress: signerAddress,
		privateKey:    privateKey,
		orderBuilder:  orderBuilder,
		tokenCache:    cache.NewTokenCache(), // 5 min TTL for token metadata
		priceCache:    cache.NewPriceCache(), // 2 sec TTL for prices
	}, nil
}

// Start starts the executor goroutine (G3)
// If tradeSignalsCh is nil, executor will use IPC to read signals from monitor
func (e *Executor) Start(ctx context.Context, tradeSignalsCh <-chan *types.TradeSignal) error {
	if e.running {
		return errors.New("executor is already running")
	}

	e.running = true

	// If channel is nil, use IPC mode
	if tradeSignalsCh == nil {
		e.useIPC = true
		log.Println("Executor attempting connection with monitor...")
		// Start IPC reader and connect to socket
		go func() {
			if err := e.ipcReader.Start(); err != nil {
				e.errorsCh <- fmt.Errorf("IPC reader failed to start: %w", err)
				return
			}

			log.Println("Connection established. Waiting for trade signals...")

			// Create internal channel for IPC signals
			ipcSignalCh := make(chan *types.TradeSignal, 100)
			ipcErrorCh := make(chan error, 10)

			// Start reading signals from IPC
			go e.ipcReader.ReadSignals(ipcSignalCh, ipcErrorCh)

			// Handle IPC errors
			go func() {
				for err := range ipcErrorCh {
					e.errorsCh <- err
				}
			}()

			// Start executor worker with IPC channel
			e.tradeSignalsCh = ipcSignalCh
			e.executorWorker(ctx)
		}()
	} else {
		// Use provided channel (in-process communication)
		e.useIPC = false
		e.tradeSignalsCh = tradeSignalsCh
		go e.executorWorker(ctx)
	}

	return nil
}

// Stop stops the executor
func (e *Executor) Stop() {
	if !e.running {
		return
	}
	close(e.stopCh)
	if e.useIPC && e.ipcReader != nil {
		if err := e.ipcReader.Stop(); err != nil {
			log.Printf("ERROR | Executor: Failed to stop IPC reader: %v", err)
		}
	}
	e.running = false
}

// Errors returns the channel that emits errors
func (e *Executor) Errors() <-chan error {
	return e.errorsCh
}

// executorWorker processes trade signals and executes orders (G3 goroutine)
func (e *Executor) executorWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case signal := <-e.tradeSignalsCh:
			if signal == nil {
				continue
			}

			// Validate signal
			if !signal.IsValid() {
				e.errorsCh <- fmt.Errorf("invalid trade signal: missing required fields")
				continue
			}

			// Execute the trade
			if err := e.executeTrade(ctx, signal); err != nil {
				e.errorsCh <- fmt.Errorf("failed to execute trade: %w", err)
				continue
			}
		}
	}
}

// executeTrade executes a trade based on a trade signal
func (e *Executor) executeTrade(ctx context.Context, signal *types.TradeSignal) error {
	log.Println("═══════════════════════════════════════════════════════════")
	log.Printf("EXECUTING TRADE | Token: %s | Side: %s | Price: %s | Size: %s",
		signal.TokenID, signal.Side, signal.Price, signal.Size)

	// 1. Check slippage
	if err := e.checkSlippage(ctx, signal); err != nil {
		return fmt.Errorf("slippage check failed: %w", err)
	}

	// 2. Check balance and scale trade size if needed
	scaledSize, err := e.checkAndScaleBalance(ctx, signal)
	if err != nil {
		return fmt.Errorf("balance check failed: %w", err)
	}

	// Update signal size if it was adjusted (either from user input or auto-scaling)
	if scaledSize != signal.Size {
		// Only log if it was auto-scaled (not user input in interactive mode)
		// In interactive mode, the user already sees the confirmation message
		if !e.config.InteractiveMode {
			log.Printf("Trade scaled: Original size: %s → Scaled size: %s (based on available balance)",
				signal.Size, scaledSize)
		}
		signal.Size = scaledSize
	}

	// 3. Build order data, generate signature, and submit
	// Order data must be built first, then signed with EIP-712
	orderID, err := e.buildAndSubmitOrder(ctx, signal)
	if err != nil {
		return fmt.Errorf("failed to submit order: %w", err)
	}

	// Log success
	headers := []string{"Status", "Order ID", "Token ID", "Side", "Price", "Size"}
	rows := [][]string{
		{
			"EXECUTED",
			orderID,
			signal.TokenID,
			string(signal.Side),
			signal.Price,
			signal.Size,
		},
	}
	log.Print(utils.FormatTable(headers, rows))
	log.Println("═══════════════════════════════════════════════════════════")

	return nil
}

// ExecuteResult contains the result of a direct trade execution
type ExecuteResult struct {
	Success      bool    // Whether the trade was successful
	OrderID      string  // Order ID from Polymarket if successful
	ErrorMessage string  // Error message if failed
	AmountUSD    float64 // Final amount traded in USD
	Price        float64 // Price at which the trade was executed
	Shares       float64 // Number of shares bought/sold
}

// ExecuteDirect executes a trade synchronously and returns the result
// This is an alternative to the channel-based Start() method
// Use this when you need immediate feedback (e.g., Telegram bot)
func (e *Executor) ExecuteDirect(ctx context.Context, signal *types.TradeSignal) (result *ExecuteResult, err error) {
	result = &ExecuteResult{
		Success: false,
	}

	// Panic recovery to prevent crashes in Telegram mode
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in ExecuteDirect: %v", r)
			result.ErrorMessage = fmt.Sprintf("internal error: %v", r)
			err = fmt.Errorf("internal error: %v", r)
		}
	}()

	if signal == nil {
		return result, errors.New("signal cannot be nil")
	}

	log.Println("═══════════════════════════════════════════════════════════")
	log.Printf("DIRECT EXECUTE | Token: %s | Side: %s | Price: %s | Size: %s | NegRisk: %v",
		signal.TokenID, signal.Side, signal.Price, signal.Size, signal.NegRisk)

	// 1. Check slippage
	if err := e.checkSlippage(ctx, signal); err != nil {
		result.ErrorMessage = fmt.Sprintf("slippage check failed: %v", err)
		return result, fmt.Errorf("slippage check failed: %w", err)
	}

	// 2. Check balance and scale trade size if needed
	// For Telegram mode, we skip interactive prompts (InteractiveMode should be false)
	scaledSize, err := e.checkAndScaleBalance(ctx, signal)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("balance check failed: %v", err)
		return result, fmt.Errorf("balance check failed: %w", err)
	}

	// Update signal size if it was adjusted
	if scaledSize != signal.Size {
		log.Printf("Trade scaled: %s → %s", signal.Size, scaledSize)
		signal.Size = scaledSize
	}

	// 3. Build order data, generate signature, and submit
	orderID, err := e.buildAndSubmitOrder(ctx, signal)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("order submission failed: %v", err)
		return result, fmt.Errorf("failed to submit order: %w", err)
	}

	// Parse the final values for result
	priceFloat, _ := strconv.ParseFloat(signal.Price, 64)
	sizeFloat, _ := strconv.ParseFloat(signal.Size, 64)

	// Calculate USD amount and shares
	// Size is in micro-USDC (6 decimals), so divide by 1,000,000
	amountUSD := sizeFloat / 1_000_000
	// Shares = amount / price (for BUY orders)
	shares := amountUSD / priceFloat

	result.Success = true
	result.OrderID = orderID
	result.AmountUSD = amountUSD
	result.Price = priceFloat
	result.Shares = shares

	log.Printf("DIRECT EXECUTE SUCCESS | Order: %s | Amount: $%.2f | Shares: %.4f",
		orderID, amountUSD, shares)
	log.Println("═══════════════════════════════════════════════════════════")

	return result, nil
}

func (e *Executor) ensureRPCClient(ctx context.Context) (*ethclient.Client, error) {
	if e.client != nil {
		return e.client, nil
	}
	if e.config.PolygonWSSURL == "" {
		return nil, fmt.Errorf("POLYGON_WSS_URL is empty; cannot create RPC client")
	}
	rpcURL := strings.Replace(e.config.PolygonWSSURL, "wss://", "https://", 1)
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Polygon RPC: %w", err)
	}
	e.client = client
	return e.client, nil
}

func (e *Executor) CheckUSDCAllowance(ctx context.Context, owner common.Address, spender common.Address) (*big.Int, error) {
	client, err := e.ensureRPCClient(ctx)
	if err != nil {
		return nil, err
	}

	parsedABI, err := getERC20AllowanceABI()
	if err != nil {
		return nil, fmt.Errorf("failed to parse ERC20 allowance ABI: %w", err)
	}

	data, err := parsedABI.Pack("allowance", owner, spender)
	if err != nil {
		return nil, fmt.Errorf("failed to pack allowance call: %w", err)
	}

	usdcAddr := common.HexToAddress(e.config.USDCContract)
	callMsg := ethereum.CallMsg{
		To:   &usdcAddr,
		Data: data,
	}
	result, err := client.CallContract(ctx, callMsg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call allowance: %w", err)
	}

	allowance := new(big.Int).SetBytes(result)
	return allowance, nil
}

func (e *Executor) CheckCTFApproval(ctx context.Context, owner common.Address, operator common.Address) (bool, error) {
	client, err := e.ensureRPCClient(ctx)
	if err != nil {
		return false, err
	}

	parsedABI, err := getERC1155ApprovalABI()
	if err != nil {
		return false, fmt.Errorf("failed to parse ERC1155 approval ABI: %w", err)
	}

	data, err := parsedABI.Pack("isApprovedForAll", owner, operator)
	if err != nil {
		return false, fmt.Errorf("failed to pack isApprovedForAll call: %w", err)
	}

	ctfAddr := common.HexToAddress(e.config.CTFContract)
	callMsg := ethereum.CallMsg{
		To:   &ctfAddr,
		Data: data,
	}
	result, err := client.CallContract(ctx, callMsg, nil)
	if err != nil {
		return false, fmt.Errorf("failed to call isApprovedForAll: %w", err)
	}

	var approved bool
	if err := parsedABI.UnpackIntoInterface(&approved, "isApprovedForAll", result); err != nil {
		return false, fmt.Errorf("failed to unpack isApprovedForAll result: %w", err)
	}
	return approved, nil
}

func maxUint256() *big.Int {
	value := new(big.Int).Lsh(big.NewInt(1), 256)
	return value.Sub(value, big.NewInt(1))
}

func (e *Executor) ApproveUSDC(ctx context.Context, spender common.Address, amount *big.Int) (common.Hash, error) {
	if e.config.SignatureType != 0 {
		return common.Hash{}, fmt.Errorf("approval execution is only supported for EOA wallets (SignatureType=0), got %d", e.config.SignatureType)
	}
	if amount == nil || amount.Sign() <= 0 {
		return common.Hash{}, errors.New("approval amount must be greater than 0")
	}

	parsedABI, err := getERC20AllowanceABI()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse ERC20 allowance ABI: %w", err)
	}
	data, err := parsedABI.Pack("approve", spender, amount)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack approve call: %w", err)
	}

	usdcAddr := common.HexToAddress(e.config.USDCContract)
	return e.executeEOATransaction(ctx, usdcAddr, data)
}

func (e *Executor) ApproveCTFAll(ctx context.Context, operator common.Address) (common.Hash, error) {
	if e.config.SignatureType != 0 {
		return common.Hash{}, fmt.Errorf("approval execution is only supported for EOA wallets (SignatureType=0), got %d", e.config.SignatureType)
	}

	parsedABI, err := getERC1155ApprovalABI()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to parse ERC1155 approval ABI: %w", err)
	}
	data, err := parsedABI.Pack("setApprovalForAll", operator, true)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack setApprovalForAll call: %w", err)
	}

	ctfAddr := common.HexToAddress(e.config.CTFContract)
	return e.executeEOATransaction(ctx, ctfAddr, data)
}

func (e *Executor) executeEOATransaction(ctx context.Context, to common.Address, data []byte) (common.Hash, error) {
	client, err := e.ensureRPCClient(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	signerAddr := common.HexToAddress(e.signerAddress)
	nonce, err := client.PendingNonceAt(ctx, signerAddr)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get gas price: %w", err)
	}

	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: signerAddr,
		To:   &to,
		Data: data,
	})
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to estimate gas: %w", err)
	}

	tx := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get chain ID: %w", err)
	}

	signedTx, err := gethtypes.SignTx(tx, gethtypes.NewEIP155Signer(chainID), e.privateKey)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	return signedTx.Hash(), nil
}

func (e *Executor) buildRelayerAuthHeaders(method, path string, body []byte) (map[string]string, error) {
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)
	if apiKey == "" || apiSecret == "" || apiPassphrase == "" {
		return nil, fmt.Errorf("builder credentials are required for relayer requests")
	}

	// Timestamp in seconds (matching official SDK: Math.floor(Date.now() / 1000))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Message format: timestamp + method + path + body (per official builder-signing-sdk)
	// Note: body is only appended if present
	message := timestamp + method + path
	if len(body) > 0 {
		message += string(body)
	}

	// Decode secret from standard base64 (per official SDK: Buffer.from(secret, "base64"))
	secretBytes, err := base64.StdEncoding.DecodeString(apiSecret)
	if err != nil {
		// If standard base64 fails, try URL-safe base64
		secretBytes, err = base64.URLEncoding.DecodeString(apiSecret)
		if err != nil {
			// Last resort: use as raw bytes
			secretBytes = []byte(apiSecret)
		}
	}

	// HMAC-SHA256
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))

	// Signature encoding: standard base64 first, then convert to URL-safe
	// (per official SDK: digest("base64") then replace + with - and / with _)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	signature := strings.ReplaceAll(strings.ReplaceAll(sig, "+", "-"), "/", "_")

	// Debug logging
	apiKeyPreview := apiKey
	if len(apiKey) > 8 {
		apiKeyPreview = apiKey[:8] + "..."
	}
	log.Printf("DEBUG | Relayer Auth - Method: %s, Path: %s, Timestamp: %s", method, path, timestamp)
	log.Printf("DEBUG | Relayer Auth - API Key: %s, Secret decoded: %d bytes", apiKeyPreview, len(secretBytes))
	log.Printf("DEBUG | Relayer Auth - Message length: %d, Signature: %s...", len(message), signature[:min(20, len(signature))])

	return map[string]string{
		"POLY_BUILDER_API_KEY":    apiKey,
		"POLY_BUILDER_PASSPHRASE": apiPassphrase,
		"POLY_BUILDER_TIMESTAMP":  timestamp,
		"POLY_BUILDER_SIGNATURE":  signature,
	}, nil
}

func decodeBuilderSecret(secret string) []byte {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return []byte{}
	}
	if b, err := base64.StdEncoding.DecodeString(secret); err == nil {
		return b
	}
	if b, err := base64.URLEncoding.DecodeString(secret); err == nil {
		return b
	}
	if b, err := base64.RawStdEncoding.DecodeString(secret); err == nil {
		return b
	}
	if b, err := base64.RawURLEncoding.DecodeString(secret); err == nil {
		return b
	}
	return []byte(secret)
}

func (e *Executor) relayerRequest(ctx context.Context, method, path string, body []byte) ([]byte, http.Header, int, error) {
	baseURL := strings.TrimRight(e.config.RelayerURL, "/")
	if baseURL == "" {
		return nil, nil, 0, errors.New("RelayerURL is required")
	}
	url := fmt.Sprintf("%s%s", baseURL, path)

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create relayer request: %w", err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
	}

	headers, err := e.buildRelayerAuthHeaders(method, path, body)
	if err != nil {
		return nil, nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("relayer request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("failed to read relayer response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header, resp.StatusCode, fmt.Errorf("relayer request failed (status=%d): %s", resp.StatusCode, truncateForLog(string(respBody), 2000))
	}
	return respBody, resp.Header, resp.StatusCode, nil
}

func (e *Executor) relayerGetNonce(ctx context.Context, signerAddress string, txType string) (string, error) {
	path := fmt.Sprintf("/nonce?address=%s&type=%s", signerAddress, txType)
	body, _, _, err := e.relayerRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	var resp relayerNonceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to parse relayer nonce response: %w", err)
	}
	if strings.TrimSpace(resp.Nonce) == "" {
		return "", errors.New("relayer nonce response was empty")
	}
	return resp.Nonce, nil
}

func (e *Executor) relayerGetRelayPayload(ctx context.Context, signerAddress string, txType string) (*relayerRelayPayloadResponse, error) {
	path := fmt.Sprintf("/relay-payload?address=%s&type=%s", signerAddress, txType)
	body, _, _, err := e.relayerRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp relayerRelayPayloadResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse relayer payload response: %w", err)
	}
	if !common.IsHexAddress(resp.Address) || strings.TrimSpace(resp.Nonce) == "" {
		return nil, fmt.Errorf("relayer payload response missing address/nonce: %+v", resp)
	}
	return &resp, nil
}

func (e *Executor) relayerGetDeployed(ctx context.Context, safeAddress string) (bool, error) {
	path := fmt.Sprintf("/deployed?address=%s", safeAddress)
	body, _, _, err := e.relayerRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	var resp struct {
		Deployed bool `json:"deployed"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("failed to parse relayer deployed response: %w", err)
	}
	return resp.Deployed, nil
}

func (e *Executor) relayerSubmit(ctx context.Context, request relayerTransactionRequest) (string, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal relayer request: %w", err)
	}
	body, _, _, err := e.relayerRequest(ctx, http.MethodPost, "/submit", payload)
	if err != nil {
		return "", err
	}
	var resp relayerSubmitResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to parse relayer submit response: %w", err)
	}
	if strings.TrimSpace(resp.TransactionID) == "" {
		return "", fmt.Errorf("relayer response missing transaction ID: %s", truncateForLog(string(body), 500))
	}
	return resp.TransactionID, nil
}

func (e *Executor) relayerGetTransaction(ctx context.Context, transactionID string) (*relayerTransaction, error) {
	path := fmt.Sprintf("/transaction?id=%s", transactionID)
	body, _, _, err := e.relayerRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp []relayerTransaction
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse relayer transaction response: %w", err)
	}
	if len(resp) == 0 {
		return nil, fmt.Errorf("relayer transaction not found: %s", transactionID)
	}
	return &resp[0], nil
}

func (e *Executor) waitForRelayerConfirmation(ctx context.Context, transactionID string) error {
	timeout := time.NewTimer(90 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer timeout.Stop()
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return fmt.Errorf("timed out waiting for relayer transaction %s", transactionID)
		case <-ticker.C:
			tx, err := e.relayerGetTransaction(ctx, transactionID)
			if err != nil {
				return err
			}
			switch tx.State {
			case relayerStateConfirmed:
				return nil
			case relayerStateFailed, relayerStateInvalid:
				return fmt.Errorf("relayer transaction %s failed (state=%s)", transactionID, tx.State)
			}
		}
	}
}

func deriveProxyWallet(factory common.Address, signer common.Address, initCodeHash common.Hash) common.Address {
	salt := crypto.Keccak256Hash(signer.Bytes())
	var saltBytes [32]byte
	copy(saltBytes[:], salt.Bytes())
	return crypto.CreateAddress2(factory, saltBytes, initCodeHash.Bytes())
}

func deriveSafeWallet(factory common.Address, signer common.Address, initCodeHash common.Hash) common.Address {
	padded := common.LeftPadBytes(signer.Bytes(), 32)
	salt := crypto.Keccak256Hash(padded)
	var saltBytes [32]byte
	copy(saltBytes[:], salt.Bytes())
	return crypto.CreateAddress2(factory, saltBytes, initCodeHash.Bytes())
}

func packSafeSignature(sig []byte) (string, error) {
	if len(sig) != 65 {
		return "", fmt.Errorf("invalid signature length: %d", len(sig))
	}
	v := sig[64]
	switch v {
	case 0, 1:
		v += 31
	case 27, 28:
		v += 4
	default:
		return "", fmt.Errorf("unexpected signature v value: %d", v)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	packed := make([]byte, 0, 65)
	packed = append(packed, common.LeftPadBytes(r.Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(s.Bytes(), 32)...)
	packed = append(packed, v)
	return hexutil.Encode(packed), nil
}

func signPersonalHash(privateKey *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	msgHash := accounts.TextHash(hash)
	sig, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		return nil, err
	}
	if sig[64] == 0 || sig[64] == 1 {
		sig[64] += 27
	}
	return sig, nil
}

func encodeProxyCallData(txns []relayerProxyCall) ([]byte, error) {
	parsedABI, err := getProxyFactoryABI()
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy factory ABI: %w", err)
	}
	calls := make([]struct {
		TypeCode uint8
		To       common.Address
		Value    *big.Int
		Data     []byte
	}, 0, len(txns))
	for _, txn := range txns {
		calls = append(calls, struct {
			TypeCode uint8
			To       common.Address
			Value    *big.Int
			Data     []byte
		}{
			TypeCode: txn.TypeCode,
			To:       txn.To,
			Value:    txn.Value,
			Data:     txn.Data,
		})
	}
	data, err := parsedABI.Pack("proxy", calls)
	if err != nil {
		return nil, fmt.Errorf("failed to pack proxy calls: %w", err)
	}
	return data, nil
}

func encodeMultiSendData(txns []relayerSafeCall) ([]byte, error) {
	parsedABI, err := getMultiSendABI()
	if err != nil {
		return nil, fmt.Errorf("failed to parse multisend ABI: %w", err)
	}
	var packed []byte
	for _, tx := range txns {
		packed = append(packed, tx.Operation)
		packed = append(packed, tx.To.Bytes()...)
		packed = append(packed, common.LeftPadBytes(tx.Value.Bytes(), 32)...)
		packed = append(packed, common.LeftPadBytes(big.NewInt(int64(len(tx.Data))).Bytes(), 32)...)
		packed = append(packed, tx.Data...)
	}
	data, err := parsedABI.Pack("multiSend", packed)
	if err != nil {
		return nil, fmt.Errorf("failed to pack multisend call: %w", err)
	}
	return data, nil
}

type relayerSafeCall struct {
	Operation uint8
	To        common.Address
	Value     *big.Int
	Data      []byte
}

type relayerProxyCall struct {
	TypeCode uint8
	To       common.Address
	Value    *big.Int
	Data     []byte
}

func buildSafeCreateSignature(
	privateKey *ecdsa.PrivateKey,
	factoryName string,
	chainID *big.Int,
	factory common.Address,
	paymentToken common.Address,
	payment *big.Int,
	paymentReceiver common.Address,
) (string, error) {
	domainTypeHash := crypto.Keccak256([]byte("EIP712Domain(string name,uint256 chainId,address verifyingContract)"))
	nameHash := crypto.Keccak256([]byte(factoryName))
	chainIDBytes := common.LeftPadBytes(chainID.Bytes(), 32)
	factoryBytes := common.LeftPadBytes(factory.Bytes(), 32)
	domainSeparator := crypto.Keccak256(append(append(append(domainTypeHash, nameHash...), chainIDBytes...), factoryBytes...))

	structTypeHash := crypto.Keccak256([]byte("CreateProxy(address paymentToken,uint256 payment,address paymentReceiver)"))
	paymentTokenBytes := common.LeftPadBytes(paymentToken.Bytes(), 32)
	paymentBytes := common.LeftPadBytes(payment.Bytes(), 32)
	paymentReceiverBytes := common.LeftPadBytes(paymentReceiver.Bytes(), 32)
	structHash := crypto.Keccak256(append(append(append(structTypeHash, paymentTokenBytes...), paymentBytes...), paymentReceiverBytes...))

	digest := crypto.Keccak256(
		[]byte("\x19\x01"),
		domainSeparator,
		structHash,
	)
	sig, err := crypto.Sign(digest, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign safe create digest: %w", err)
	}
	if sig[64] == 0 || sig[64] == 1 {
		sig[64] += 27
	}
	return hexutil.Encode(sig), nil
}

func buildSafeTransactionDigest(
	chainID *big.Int,
	safe common.Address,
	tx relayerSafeCall,
	safeTxGas *big.Int,
	baseGas *big.Int,
	gasPrice *big.Int,
	gasToken common.Address,
	refundReceiver common.Address,
	nonce *big.Int,
) []byte {
	domainTypeHash := crypto.Keccak256([]byte("EIP712Domain(uint256 chainId,address verifyingContract)"))
	chainIDBytes := common.LeftPadBytes(chainID.Bytes(), 32)
	safeBytes := common.LeftPadBytes(safe.Bytes(), 32)
	domainSeparator := crypto.Keccak256(append(append(domainTypeHash, chainIDBytes...), safeBytes...))

	structTypeHash := crypto.Keccak256([]byte("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"))
	toBytes := common.LeftPadBytes(tx.To.Bytes(), 32)
	valueBytes := common.LeftPadBytes(tx.Value.Bytes(), 32)
	dataHash := crypto.Keccak256(tx.Data)
	operationBytes := common.LeftPadBytes([]byte{tx.Operation}, 32)
	safeTxGasBytes := common.LeftPadBytes(safeTxGas.Bytes(), 32)
	baseGasBytes := common.LeftPadBytes(baseGas.Bytes(), 32)
	gasPriceBytes := common.LeftPadBytes(gasPrice.Bytes(), 32)
	gasTokenBytes := common.LeftPadBytes(gasToken.Bytes(), 32)
	refundReceiverBytes := common.LeftPadBytes(refundReceiver.Bytes(), 32)
	nonceBytes := common.LeftPadBytes(nonce.Bytes(), 32)

	structHash := crypto.Keccak256(append(append(append(append(append(append(append(append(append(append(
		structTypeHash,
		toBytes...),
		valueBytes...),
		dataHash...),
		operationBytes...),
		safeTxGasBytes...),
		baseGasBytes...),
		gasPriceBytes...),
		gasTokenBytes...),
		refundReceiverBytes...),
		nonceBytes...))

	return crypto.Keccak256(
		[]byte("\x19\x01"),
		domainSeparator,
		structHash,
	)
}

func buildProxyStructHash(
	from common.Address,
	to common.Address,
	data []byte,
	txFee *big.Int,
	gasPrice *big.Int,
	gasLimit *big.Int,
	nonce *big.Int,
	relayHub common.Address,
	relay common.Address,
) []byte {
	buf := make([]byte, 0, 4+20+20+len(data)+32*4+20+20)
	buf = append(buf, []byte("rlx:")...)
	buf = append(buf, from.Bytes()...)
	buf = append(buf, to.Bytes()...)
	buf = append(buf, data...)
	buf = append(buf, common.LeftPadBytes(txFee.Bytes(), 32)...)
	buf = append(buf, common.LeftPadBytes(gasPrice.Bytes(), 32)...)
	buf = append(buf, common.LeftPadBytes(gasLimit.Bytes(), 32)...)
	buf = append(buf, common.LeftPadBytes(nonce.Bytes(), 32)...)
	buf = append(buf, relayHub.Bytes()...)
	buf = append(buf, relay.Bytes()...)
	return crypto.Keccak256(buf)
}

// checkSlippage verifies that price hasn't moved beyond tolerance
// If MaxSlippage <= 0, slippage check is disabled (user decides)
func (e *Executor) checkSlippage(ctx context.Context, signal *types.TradeSignal) error {
	// Skip slippage check if disabled (MaxSlippage <= 0)
	if signal.MaxSlippage <= 0 {
		log.Printf("Slippage check disabled (MaxSlippage=%d)", signal.MaxSlippage)
		return nil
	}

	// Get current market price (requires side parameter for BUY/SELL price)
	currentPrice, err := e.getCurrentPrice(ctx, signal.TokenID, signal.Side)
	if err != nil {
		return fmt.Errorf("failed to get current price: %w", err)
	}

	// Parse prices
	signalPrice, err := strconv.ParseFloat(signal.Price, 64)
	if err != nil {
		return fmt.Errorf("invalid signal price: %w", err)
	}

	// Calculate slippage
	slippage, err := utils.CalculateSlippage(signal.Price, currentPrice)
	if err != nil {
		return fmt.Errorf("failed to calculate slippage: %w", err)
	}

	// Check if slippage exceeds tolerance
	if slippage > float64(signal.MaxSlippage) {
		return fmt.Errorf("slippage %.2f%% exceeds tolerance of %d%% (signal price: %.4f, current: %s)",
			slippage, signal.MaxSlippage, signalPrice, currentPrice)
	}

	log.Printf("Slippage check passed: %.2f%% (tolerance: %d%%)", slippage, signal.MaxSlippage)
	return nil
}

// checkAndScaleBalance verifies balance and scales trade size if needed
// Returns the scaled size (may be smaller than original if balance is insufficient)
func (e *Executor) checkAndScaleBalance(ctx context.Context, signal *types.TradeSignal) (string, error) {
	// Connect to Polygon if not already connected
	if e.client == nil {
		client, err := ethclient.DialContext(ctx, strings.Replace(e.config.PolygonWSSURL, "wss://", "https://", 1))
		if err != nil {
			return "", fmt.Errorf("failed to connect to Polygon: %w", err)
		}
		e.client = client
	}

	// For BUY orders, we need to check USDC balance
	if signal.Side != types.OrderSideBuy {
		// For SELL orders, we check if we have the shares (simplified for now)
		return signal.Size, nil
	}

	// Get USDC.e balance using ERC20 balanceOf
	usdcContract := common.HexToAddress(e.config.USDCContract)
	funderAddr := common.HexToAddress(e.config.FunderAddress)

	// ERC20 balanceOf(address) function signature
	// balanceOf(address) = 0x70a08231
	balanceOfSig := common.Hex2Bytes("70a08231")
	addressParam := common.LeftPadBytes(funderAddr.Bytes(), 32)
	balanceOfData := append(balanceOfSig, addressParam...)

	// Call the contract
	result, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &usdcContract,
		Data: balanceOfData,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get USDC balance: %w", err)
	}

	balance := new(big.Int).SetBytes(result)

	// Parse order size (micro-USDC for Telegram, shares for interactive)
	sizeFloat, err := strconv.ParseFloat(signal.Size, 64)
	if err != nil {
		return "", fmt.Errorf("invalid size: %w", err)
	}

	// Convert balance to dollars for logging
	balanceDollars := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(1_000_000))
	balanceDollarStr, _ := balanceDollars.Float64()

	// Check if balance is below minimum
	if balance.Cmp(e.config.MinTradeAmount) < 0 {
		minTradeDollarStr, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
		return "", fmt.Errorf("insufficient balance: have $%.2f, need at least $%.2f (minimum trade amount)",
			balanceDollarStr, minTradeDollarStr)
	}

	// Interactive mode: prompt user for trade amount (used by CLI, not Telegram)
	if e.config.InteractiveMode {
		// Parse price for interactive calculations
		priceFloat, err := strconv.ParseFloat(signal.Price, 64)
		if err != nil {
			return "", fmt.Errorf("invalid price: %w", err)
		}
		// Calculate required amount for display (sizeFloat is shares in interactive mode)
		requiredDollars := sizeFloat * priceFloat

		userAmount, err := e.promptTradeAmount(balanceDollarStr, requiredDollars, priceFloat)
		if err != nil {
			return "", fmt.Errorf("user input cancelled or invalid: %w", err)
		}

		// Verify minimum trade amount (compare entered amount directly, not calculated cost)
		// This avoids rounding issues when calculating shares and converting back
		userAmountUSDC := big.NewInt(int64(userAmount * 1_000_000))
		if userAmountUSDC.Cmp(e.config.MinTradeAmount) < 0 {
			minTradeDollarStr, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
			return "", fmt.Errorf("entered amount $%.2f is below minimum trade amount $%.2f", userAmount, minTradeDollarStr)
		}

		// Calculate shares from user-entered dollar amount
		// shares = (userAmount / price)
		priceInUSDC := big.NewInt(int64(priceFloat * 1_000_000))
		userShares := new(big.Int).Div(new(big.Int).Mul(userAmountUSDC, big.NewInt(1_000_000)), priceInUSDC)

		// Ensure we have at least 1 share
		if userShares.Sign() <= 0 {
			return "", fmt.Errorf("calculated shares (%s) is too small for price $%.4f", userShares.String(), priceFloat)
		}

		// Verify user has enough balance
		if userAmountUSDC.Cmp(balance) > 0 {
			return "", fmt.Errorf("entered amount $%.2f exceeds available balance $%.2f", userAmount, balanceDollarStr)
		}

		scaledSize := userShares.String()
		log.Printf("User entered: $%.2f → %s shares at $%.4f", userAmount, scaledSize, priceFloat)
		return scaledSize, nil
	}

	// Non-interactive (Telegram) mode: signal.Size is already micro-USDC (user-selected amount)
	// Just validate balance is sufficient - don't try to scale
	requestedUSDC := big.NewInt(int64(sizeFloat)) // sizeFloat IS micro-USDC, not shares
	log.Printf("Balance: $%.2f | Requested: $%.2f",
		balanceDollarStr, float64(requestedUSDC.Int64())/1_000_000)

	// Check if user has enough balance for the requested amount
	if balance.Cmp(requestedUSDC) < 0 {
		return "", fmt.Errorf("insufficient balance: have $%.2f, need $%.2f",
			balanceDollarStr, float64(requestedUSDC.Int64())/1_000_000)
	}

	log.Printf("Balance check passed: sufficient funds available")
	return signal.Size, nil
}

// promptTradeAmount prompts the user to enter the trade amount in dollars
// Returns the dollar amount entered by the user
func (e *Executor) promptTradeAmount(balance, required, price float64) (float64, error) {
	log.Println("═══════════════════════════════════════════════════════════")
	log.Printf("TRADE SIGNAL RECEIVED")
	log.Printf("  Available Balance: $%.2f", balance)
	log.Printf("  Original Trade Size: $%.2f", required)
	log.Printf("  Price per share: $%.4f", price)
	log.Println("═══════════════════════════════════════════════════════════")
	log.Print("Enter amount to spend (USD, minimum $1) or 'skip' to cancel: ")

	// Create a channel to receive user input
	inputChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// Read input in a goroutine with timeout
	go func() {
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			errChan <- err
			return
		}
		inputChan <- strings.TrimSpace(input)
	}()

	// Wait for input with 30 second timeout
	select {
	case input := <-inputChan:
		// User entered input
		if strings.ToLower(input) == "skip" || strings.ToLower(input) == "cancel" {
			return 0, fmt.Errorf("user cancelled")
		}

		// Parse dollar amount
		amount, err := strconv.ParseFloat(input, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid amount: %w", err)
		}

		// Get minimum trade amount from config (convert from USDC units to dollars)
		minTradeDollars := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000))
		minTradeFloat, _ := minTradeDollars.Float64()

		if amount < minTradeFloat {
			return 0, fmt.Errorf("amount must be at least $%.2f", minTradeFloat)
		}

		return amount, nil

	case err := <-errChan:
		return 0, fmt.Errorf("failed to read input: %w", err)

	case <-time.After(30 * time.Second):
		return 0, fmt.Errorf("timeout: no input received within 30 seconds")
	}
}

// buildAndSubmitOrder builds order data using the official Polymarket library, signs it, and submits to the API
func (e *Executor) buildAndSubmitOrder(ctx context.Context, signal *types.TradeSignal) (string, error) {
	// Parse price
	price, err := strconv.ParseFloat(signal.Price, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse price: %w", err)
	}

	orderType := strings.ToUpper(strings.TrimSpace(signal.OrderType))
	if orderType == "" {
		orderType = "FAK"
	}

	// If NegRisk flag is unknown, fetch it from CLOB API to use the correct verifying contract
	if !signal.NegRisk {
		if negRisk, err := e.getNegRisk(ctx, signal.TokenID); err == nil {
			signal.NegRisk = negRisk
			log.Printf("DEBUG | NegRisk fetched from API: %v", negRisk)
		} else {
			log.Printf("WARN | Failed to fetch negRisk for token %s: %v (defaulting to %v)", signal.TokenID, err, signal.NegRisk)
		}
	}

	sizeRaw, err := strconv.ParseInt(signal.Size, 10, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse size: %w", err)
	}

	// Calculate makerAmount and takerAmount based on side and price.
	//
	// This follows Polymarket's official TS client semantics:
	// - BUY: makerAmount = USDC, takerAmount = shares
	// - SELL: makerAmount = shares, takerAmount = USDC
	//
	// Rounding rules:
	// - Price is rounded to the market's tick size precision (priceDecimals).
	// - USDC amounts (maker for BUY / taker for SELL) must be <= 2 decimals (per API enforcement).
	// - Share amounts (taker for BUY / maker for SELL) may support up to 5 decimals on some markets.
	var makerAmount, takerAmount int64
	var side int
	if sizeRaw <= 0 {
		return "", fmt.Errorf("trade size must be > 0 (got %d)", sizeRaw)
	}

	tickSize, err := e.getTickSize(ctx, signal.TokenID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tick size for token %s: %w", signal.TokenID, err)
	}
	rc, err := roundConfigForTickSize(tickSize)
	if err != nil {
		return "", fmt.Errorf("failed to resolve rounding config for tick size %s (token %s): %w", tickSize, signal.TokenID, err)
	}

	var usdcMicroRounded int64
	var sharesMicroRounded int64
	if signal.Side == types.OrderSideSell && signal.SizeIsShares {
		usdcMicroRounded, sharesMicroRounded, err = computeOrderMicroAmountsFromShares(
			rc,
			orderType,
			signal.Price,
			sizeRaw,
		)
	} else {
		// In Telegram execution, signal.Size is treated as an amount of USDC (micro-USDC, 6 decimals).
		// UserMonitor.ExecuteTrade enforces this by overwriting Size based on the user-selected USD amount.
		usdcMicroRounded, sharesMicroRounded, err = computeOrderMicroAmounts(
			rc,
			orderType,
			signal.Price,
			sizeRaw,
		)
	}
	if err != nil {
		return "", fmt.Errorf("failed to compute order amounts: %w", err)
	}
	amountUSDCMicro := usdcMicroRounded

	log.Printf("DEBUG | Rounding config for tick-size %s: priceDecimals=%d, sizeDecimals=%d, amountDecimals=%d", tickSize, rc.priceDecimals, rc.sizeDecimals, rc.amountDecimals)
	log.Printf("DEBUG | Final amounts: USDC=%d micro ($%.6f), shares=%d micro (%.6f shares)",
		usdcMicroRounded, float64(usdcMicroRounded)/1_000_000,
		sharesMicroRounded, float64(sharesMicroRounded)/1_000_000)

	// Validate minimum order size (in shares)
	sharesFloat := float64(sharesMicroRounded) / 1_000_000
	minOrderSize, err := e.getMinOrderSize(ctx, signal.TokenID)
	if err != nil {
		log.Printf("WARN | Failed to fetch min order size, using default 5: %v", err)
		minOrderSize = 5.0
	}
	if sharesFloat < minOrderSize {
		priceFloat, _ := strconv.ParseFloat(signal.Price, 64)
		minUSD := minOrderSize * priceFloat
		return "", fmt.Errorf("order size %.2f shares is below minimum %.0f shares. You need at least $%.2f at current price (%.1f¢) to trade this market",
			sharesFloat, minOrderSize, minUSD, priceFloat*100)
	}

	if signal.Side == types.OrderSideBuy {
		side = model.BUY // 0
		makerAmount = usdcMicroRounded
		takerAmount = sharesMicroRounded
	} else {
		side = model.SELL // 1
		makerAmount = sharesMicroRounded
		takerAmount = usdcMicroRounded
	}

	makerAmountStr := strconv.FormatInt(makerAmount, 10)
	takerAmountStr := strconv.FormatInt(takerAmount, 10)

	// Determine signature type from config
	// model.SignatureType is just an int: EOA=0, POLY_PROXY=1, POLY_GNOSIS_SAFE=2
	signatureType := e.config.SignatureType
	if signatureType < 0 || signatureType > 2 {
		signatureType = model.POLY_GNOSIS_SAFE
	}

	// Fetch the fee rate for this token
	feeRateBps, err := e.getFeeRate(ctx, signal.TokenID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch fee rate for token %s: %w", signal.TokenID, err)
	}
	log.Printf("DEBUG | Using feeRateBps=%s for token %s", feeRateBps, signal.TokenID)

	// Build order data using official Polymarket library types
	expiration := "0"
	if orderType == "GTD" {
		if signal.ExpirationUnix <= 0 {
			return "", fmt.Errorf("order type GTD requires ExpirationUnix > 0 (got %d)", signal.ExpirationUnix)
		}
		expiration = fmt.Sprintf("%d", signal.ExpirationUnix)
	}
	orderData := &model.OrderData{
		Maker:         e.config.FunderAddress,
		Signer:        e.signerAddress,
		Taker:         "0x0000000000000000000000000000000000000000",
		TokenId:       signal.TokenID,
		MakerAmount:   makerAmountStr,
		TakerAmount:   takerAmountStr,
		Side:          side,
		Expiration:    expiration,
		Nonce:         "0",
		FeeRateBps:    feeRateBps,
		SignatureType: signatureType,
	}

	// Determine which exchange contract to use based on NegRisk
	// model.VerifyingContract is just an int: CTFExchange=0, NegRiskCTFExchange=1
	var contract int
	if signal.NegRisk {
		contract = model.NegRiskCTFExchange
		log.Printf("DEBUG | Using NegRiskCTFExchange (NegRisk market)")
	} else {
		contract = model.CTFExchange
		log.Printf("DEBUG | Using CTFExchange (regular market)")
	}

	log.Printf("DEBUG | Order: side=%d, price=%.6f, amountUSDCMicro=%d, makerAmount=%s, takerAmount=%s, negRisk=%v, signatureType=%d",
		side, price, amountUSDCMicro, makerAmountStr, takerAmountStr, signal.NegRisk, e.config.SignatureType)

	// Use official Polymarket library to build and sign the order
	signedOrder, err := e.orderBuilder.BuildSignedOrder(e.privateKey, orderData, contract)
	if err != nil {
		return "", fmt.Errorf("failed to build signed order: %w", err)
	}

	log.Printf("DEBUG | Official library signed order:")
	log.Printf("  Salt: %s", signedOrder.Order.Salt.String())
	log.Printf("  Maker (Funder): %s", signedOrder.Order.Maker.Hex())
	log.Printf("  Signer (EOA): %s", signedOrder.Order.Signer.Hex())
	log.Printf("  Taker: %s", signedOrder.Order.Taker.Hex())
	log.Printf("  TokenId: %s", signedOrder.Order.TokenId.String())
	log.Printf("  MakerAmount: %s", signedOrder.Order.MakerAmount.String())
	log.Printf("  TakerAmount: %s", signedOrder.Order.TakerAmount.String())
	log.Printf("  FeeRateBps: %s", signedOrder.Order.FeeRateBps.String())
	log.Printf("  Side: %d (0=BUY, 1=SELL)", signedOrder.Order.Side.Int64())
	log.Printf("  SignatureType: %d (0=EOA, 1=POLY_PROXY, 2=POLY_GNOSIS_SAFE)", signedOrder.Order.SignatureType.Int64())
	log.Printf("  Signature: %s (redacted)", redactForLog(hexutil.Encode(signedOrder.Signature)))
	log.Printf("  Signature length: %d bytes (expected: 65)", len(signedOrder.Signature))
	log.Printf("DEBUG | Critical verification:")
	log.Printf("  - Signer address in order: %s", signedOrder.Order.Signer.Hex())
	log.Printf("  - Signer address from config: %s", e.signerAddress)
	log.Printf("  - These MUST match! (API key is tied to signer address)")
	log.Printf("  - Maker (0x7234...) should be your Polymarket DEPOSIT ADDRESS")
	log.Printf("  - Signer (0xaB3A...) should be your MetaMask ADDRESS")

	// Submit order with signature from the official library
	return e.submitSignedOrderFromLib(ctx, signal, signedOrder)
}

// submitSignedOrderFromLib submits a signed order (from official library) to the CLOB API
func (e *Executor) submitSignedOrderFromLib(ctx context.Context, signal *types.TradeSignal, signedOrder *model.SignedOrder) (string, error) {
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)

	// Convert Side to string for API
	// signedOrder.Order.Side is a *big.Int
	sideStr := "BUY"
	if signedOrder.Order.Side.Int64() == 1 {
		sideStr = "SELL"
	}

	// Construct the signed order object from the library's SignedOrder
	orderPayloadOrder := map[string]interface{}{
		"salt":          signedOrder.Order.Salt.Int64(),
		"maker":         signedOrder.Order.Maker.Hex(),
		"signer":        signedOrder.Order.Signer.Hex(),
		"taker":         signedOrder.Order.Taker.Hex(),
		"tokenId":       signedOrder.Order.TokenId.String(),
		"makerAmount":   signedOrder.Order.MakerAmount.String(),
		"takerAmount":   signedOrder.Order.TakerAmount.String(),
		"side":          sideStr,
		"expiration":    signedOrder.Order.Expiration.String(),
		"nonce":         signedOrder.Order.Nonce.String(),
		"feeRateBps":    signedOrder.Order.FeeRateBps.String(),
		"signatureType": int(signedOrder.Order.SignatureType.Int64()),
		"signature":     hexutil.Encode(signedOrder.Signature),
	}

	// Construct full order payload
	orderType := strings.ToUpper(strings.TrimSpace(signal.OrderType))
	if orderType == "" {
		orderType = "FAK"
	}
	// Validate order type - Polymarket supports: FAK, FOK, GTC, GTD
	validOrderTypes := map[string]bool{
		"FAK": true,
		"FOK": true,
		"GTC": true,
		"GTD": true,
	}
	if !validOrderTypes[orderType] {
		return "", fmt.Errorf("unsupported order type %q (supported: FAK, FOK, GTC, GTD)", orderType)
	}

	orderPayload := map[string]interface{}{
		"deferExec": false,
		"order":     orderPayloadOrder,
		"owner":     apiKey,
		"orderType": orderType,
	}

	if err := e.ensureOrderApprovals(ctx, signal, signedOrder.Order.Maker, signedOrder.Order.MakerAmount); err != nil {
		return "", err
	}

	// Marshal JSON - Go's json.Marshal produces compact JSON
	payloadBytes, err := json.Marshal(orderPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal order: %w", err)
	}

	// Create request with body - endpoint is /order (singular)
	url := fmt.Sprintf("%s/order", e.config.CLOBAPIURL)
	bodyReader := strings.NewReader(string(payloadBytes))
	req, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers with L2 authentication (HMAC-SHA256)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "polycatch/1.0")

	// Trim whitespace from credentials (common issue when copying from UI)
	// apiKey is already defined above for the owner field
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	// Validate credentials are not empty
	if apiKey == "" {
		return "", fmt.Errorf("BUILDER_API_KEY is empty")
	}
	if apiSecret == "" {
		return "", fmt.Errorf("BUILDER_SECRET is empty")
	}
	if apiPassphrase == "" {
		return "", fmt.Errorf("BUILDER_PASSPHRASE is empty")
	}

	// Validate API key format (should be UUID-like, 36 chars with dashes or 32 without)
	if len(apiKey) != 36 && len(apiKey) != 32 {
		log.Printf("WARNING | API key length is %d (expected 32 or 36 for UUID format)", len(apiKey))
	}

	// Generate L2 authentication headers according to Polymarket docs
	// Headers: POLY_ADDRESS, POLY_SIGNATURE (HMAC-SHA256), POLY_TIMESTAMP, POLY_API_KEY, POLY_PASSPHRASE
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: timestamp + method + path + body (per official Polymarket client)
	path := "/order"
	body := string(payloadBytes)
	message := fmt.Sprintf("%s%s%s%s", timestamp, "POST", path, body)

	// Generate HMAC-SHA256 signature
	secretBytes := decodeBuilderSecret(apiSecret)
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	// Encode signature using base64 URL-safe encoding (per official client)
	hmacSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Debug logging to help diagnose authentication issues
	log.Printf("DEBUG | L2 Auth - Timestamp: %s, Path: %s, Body length: %d", timestamp, path, len(body))
	apiKeyPreview := apiKey
	if len(apiKey) > 8 {
		apiKeyPreview = apiKey[:8] + "..."
	}
	messagePreview := message
	if len(message) > 150 {
		messagePreview = message[:150] + "..."
	}
	log.Printf("DEBUG | L2 Auth - Signer Address: %s", e.signerAddress)
	log.Printf("DEBUG | L2 Auth - API Key: %s (length: %d)", apiKeyPreview, len(apiKey))
	log.Printf("DEBUG | L2 Auth - Message: %s", messagePreview)
	log.Printf("DEBUG | L2 Auth - Secret decoded: %d bytes", len(secretBytes))
	log.Printf("DEBUG | L2 Auth - Signature: %s (redacted)", redactForLog(hmacSignature))
	log.Printf("DEBUG | Payload bytes: %d", len(payloadBytes))

	// Set L2 authentication headers
	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_SIGNATURE", hmacSignature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)

	// Execute request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("DEBUG | API Error Response bytes: %d", len(bodyBytes))
		log.Printf("DEBUG | Request Payload bytes: %d", len(payloadBytes))
		log.Printf("DEBUG | Polymarket response status: %d, content-type: %s", resp.StatusCode, resp.Header.Get("Content-Type"))

		reqIDs := extractPolymarketRequestIDs(resp.Header)
		if reqIDs != nil {
			log.Printf("DEBUG | Polymarket response request IDs: %+v", reqIDs)
		}

		if looksLikeCloudflareBlock(resp, bodyBytes) {
			return "", fmt.Errorf(
				"Polymarket request blocked by Cloudflare (status=%d). This is usually due to datacenter IP reputation / bot protection.\n"+
					"Request IDs: %+v\n"+
					"Response preview: %s",
				resp.StatusCode,
				reqIDs,
				truncateForLog(strings.TrimSpace(string(bodyBytes)), 800),
			)
		}

		// Log a high-signal summary of the error response for debugging.
		bodySummary := formatPolymarketAPIErrorBody(bodyBytes)
		if bodySummary != "" {
			log.Printf("DEBUG | Polymarket error response summary: %s", bodySummary)
		}

		// For 4xx errors, also log a sanitized preview of the payload (signatures redacted).
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			payloadPreview := truncateForLog(sanitizeOrderPayloadForLog(payloadBytes), 2000)
			log.Printf("DEBUG | Polymarket request payload preview (sanitized): %s", payloadPreview)
		}

		// Enhanced error message for 401 errors
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf("API returned 401 Unauthorized: %s\n"+
				"Troubleshooting:\n"+
				"1. Verify BUILDER_API_KEY matches the API key from Polymarket Builder Dashboard\n"+
				"2. Verify SIGNER_PRIVATE_KEY corresponds to the address used to create the API key\n"+
				"3. Verify BUILDER_SECRET and BUILDER_PASSPHRASE are correct\n"+
				"4. Ensure the API key was created using L1 authentication with the correct signer address\n"+
				"5. Check that POLY_ADDRESS (%s) matches the address used during API key creation",
				truncateForLog(string(bodyBytes), 2000), e.signerAddress)
		}

		// Enhanced error for 400 errors
		if resp.StatusCode == http.StatusBadRequest {
			return "", fmt.Errorf("API returned 400 Bad Request: %s", truncateForLog(string(bodyBytes), 2000))
		}

		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, truncateForLog(string(bodyBytes), 2000))
	}

	// Parse response
	var orderResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &orderResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract order ID - API returns "orderID" (capital ID) or "orderId" (camelCase)
	orderID, ok := orderResponse["orderID"].(string)
	if !ok {
		orderID, ok = orderResponse["orderId"].(string)
	}
	if !ok {
		// Try alternative field names
		if id, ok := orderResponse["id"].(string); ok {
			orderID = id
		} else {
			return "", fmt.Errorf("order ID not found in response: %s", string(bodyBytes))
		}
	}

	// Log order status if available
	if status, ok := orderResponse["status"].(string); ok {
		log.Printf("✅ Order submitted successfully! OrderID: %s, Status: %s", orderID, status)
		if success, ok := orderResponse["success"].(bool); ok && success {
			log.Printf("✅ API confirmed success: true")
		}
	} else {
		log.Printf("✅ Order submitted successfully! OrderID: %s", orderID)
	}

	return orderID, nil
}

func (e *Executor) ensureOrderApprovals(
	ctx context.Context,
	signal *types.TradeSignal,
	maker common.Address,
	makerAmount *big.Int,
) error {
	if signal == nil {
		return errors.New("trade signal cannot be nil")
	}
	if makerAmount == nil {
		return errors.New("maker amount cannot be nil")
	}

	missingUSDC, missingCTF, err := e.findMissingApprovals(ctx, signal, maker, makerAmount)
	if err != nil {
		return err
	}

	if len(missingUSDC) == 0 && len(missingCTF) == 0 {
		return nil
	}

	if e.config.SignatureType != 0 {
		return e.executeRelayerApprovals(ctx, maker, missingUSDC, missingCTF)
	}

	for _, spender := range missingUSDC {
		txHash, err := e.ApproveUSDC(ctx, spender, maxUint256())
		if err != nil {
			return fmt.Errorf("failed to approve USDC for %s: %w", spender.Hex(), err)
		}
		if err := e.waitForTxReceipt(ctx, txHash); err != nil {
			return fmt.Errorf("USDC approval tx failed for %s: %w", spender.Hex(), err)
		}
	}

	for _, operator := range missingCTF {
		txHash, err := e.ApproveCTFAll(ctx, operator)
		if err != nil {
			return fmt.Errorf("failed to approve CTF tokens for %s: %w", operator.Hex(), err)
		}
		if err := e.waitForTxReceipt(ctx, txHash); err != nil {
			return fmt.Errorf("CTF approval tx failed for %s: %w", operator.Hex(), err)
		}
	}

	return nil
}

// EnsureDefaultApprovals checks and submits approvals for common contracts
// without requiring a specific order context.
func (e *Executor) EnsureDefaultApprovals(ctx context.Context) error {
	maker := common.HexToAddress(e.config.FunderAddress)

	var missingUSDC []common.Address
	var missingCTF []common.Address

	for _, spender := range e.requiredUSDCSpenders(true) {
		allowance, err := e.CheckUSDCAllowance(ctx, maker, spender)
		if err != nil {
			return fmt.Errorf("failed to check USDC allowance for %s: %w", spender.Hex(), err)
		}
		if allowance.Sign() == 0 {
			missingUSDC = append(missingUSDC, spender)
		}
	}

	for _, operator := range e.requiredCTFOperators(true) {
		approved, err := e.CheckCTFApproval(ctx, maker, operator)
		if err != nil {
			return fmt.Errorf("failed to check CTF approval for %s: %w", operator.Hex(), err)
		}
		if !approved {
			missingCTF = append(missingCTF, operator)
		}
	}

	if len(missingUSDC) == 0 && len(missingCTF) == 0 {
		return nil
	}

	if e.config.SignatureType != 0 {
		return e.executeRelayerApprovals(ctx, maker, missingUSDC, missingCTF)
	}

	for _, spender := range missingUSDC {
		txHash, err := e.ApproveUSDC(ctx, spender, maxUint256())
		if err != nil {
			return fmt.Errorf("failed to approve USDC for %s: %w", spender.Hex(), err)
		}
		if err := e.waitForTxReceipt(ctx, txHash); err != nil {
			return fmt.Errorf("USDC approval tx failed for %s: %w", spender.Hex(), err)
		}
	}

	for _, operator := range missingCTF {
		txHash, err := e.ApproveCTFAll(ctx, operator)
		if err != nil {
			return fmt.Errorf("failed to approve CTF tokens for %s: %w", operator.Hex(), err)
		}
		if err := e.waitForTxReceipt(ctx, txHash); err != nil {
			return fmt.Errorf("CTF approval tx failed for %s: %w", operator.Hex(), err)
		}
	}

	return nil
}

func (e *Executor) executeRelayerApprovals(
	ctx context.Context,
	maker common.Address,
	missingUSDC []common.Address,
	missingCTF []common.Address,
) error {
	if e.config.SignatureType != 1 && e.config.SignatureType != 2 {
		return fmt.Errorf("unsupported SignatureType for relayer approvals: %d", e.config.SignatureType)
	}
	if len(missingUSDC) == 0 && len(missingCTF) == 0 {
		return nil
	}

	switch e.config.SignatureType {
	case 1:
		return e.executeProxyApprovals(ctx, maker, missingUSDC, missingCTF)
	case 2:
		return e.executeSafeApprovals(ctx, maker, missingUSDC, missingCTF)
	default:
		return fmt.Errorf("unsupported SignatureType for relayer approvals: %d", e.config.SignatureType)
	}
}

func (e *Executor) relayerWalletTypeLabel() string {
	if e.config.SignatureType == 1 {
		return "proxy"
	}
	if e.config.SignatureType == 2 {
		return "safe"
	}
	return "unknown"
}

func (e *Executor) expectedRelayerWallet() (common.Address, error) {
	signer := common.HexToAddress(e.signerAddress)
	if e.config.SignatureType == 1 {
		factory := common.HexToAddress(e.config.RelayerProxyFactory)
		initCodeHash := common.HexToHash(e.config.RelayerProxyInitCode)
		return deriveProxyWallet(factory, signer, initCodeHash), nil
	}
	if e.config.SignatureType == 2 {
		factory := common.HexToAddress(e.config.RelayerSafeFactory)
		initCodeHash := common.HexToHash(e.config.RelayerSafeInitCode)
		return deriveSafeWallet(factory, signer, initCodeHash), nil
	}
	return common.Address{}, fmt.Errorf("unsupported SignatureType for relayer wallet derivation: %d", e.config.SignatureType)
}

func (e *Executor) executeProxyApprovals(
	ctx context.Context,
	proxyWallet common.Address,
	missingUSDC []common.Address,
	missingCTF []common.Address,
) error {
	relayPayload, err := e.relayerGetRelayPayload(ctx, e.signerAddress, "PROXY")
	if err != nil {
		return fmt.Errorf("failed to get relayer payload: %w", err)
	}

	calls, err := e.buildApprovalCalls(missingUSDC, missingCTF)
	if err != nil {
		return err
	}
	if len(calls) == 0 {
		return nil
	}

	proxyCalls := make([]relayerProxyCall, 0, len(calls))
	for _, call := range calls {
		proxyCalls = append(proxyCalls, relayerProxyCall{
			TypeCode: 1,
			To:       call.To,
			Value:    call.Value,
			Data:     call.Data,
		})
	}
	encodedCalls, err := encodeProxyCallData(proxyCalls)
	if err != nil {
		return err
	}

	nonce, ok := new(big.Int).SetString(relayPayload.Nonce, 10)
	if !ok {
		return fmt.Errorf("invalid relayer nonce: %s", relayPayload.Nonce)
	}
	gasLimit := new(big.Int).SetUint64(e.config.RelayerProxyGasLimit)
	relayAddr := common.HexToAddress(relayPayload.Address)
	relayHub := common.HexToAddress(e.config.RelayerRelayHub)
	proxyFactory := common.HexToAddress(e.config.RelayerProxyFactory)
	txFee := big.NewInt(0)
	gasPrice := big.NewInt(0)
	structHash := buildProxyStructHash(
		common.HexToAddress(e.signerAddress),
		proxyFactory,
		encodedCalls,
		txFee,
		gasPrice,
		gasLimit,
		nonce,
		relayHub,
		relayAddr,
	)
	sig, err := signPersonalHash(e.privateKey, structHash)
	if err != nil {
		return fmt.Errorf("failed to sign proxy approval: %w", err)
	}

	request := relayerTransactionRequest{
		Type:        "PROXY",
		From:        e.signerAddress,
		To:          proxyFactory.Hex(),
		ProxyWallet: proxyWallet.Hex(),
		Data:        hexutil.Encode(encodedCalls),
		Nonce:       relayPayload.Nonce,
		Signature:   hexutil.Encode(sig),
		SignatureParams: relayerProxySignatureParams{
			GasPrice:   "0",
			GasLimit:   gasLimit.String(),
			RelayerFee: "0",
			RelayHub:   relayHub.Hex(),
			Relay:      relayAddr.Hex(),
		},
		Metadata: "polycatch approvals",
	}
	transactionID, err := e.relayerSubmit(ctx, request)
	if err != nil {
		return err
	}
	return e.waitForRelayerConfirmation(ctx, transactionID)
}

func (e *Executor) executeSafeApprovals(
	ctx context.Context,
	safeAddress common.Address,
	missingUSDC []common.Address,
	missingCTF []common.Address,
) error {
	if strings.TrimSpace(e.config.RelayerURL) == "" {
		return errors.New("RELAYER_URL is required for safe approvals (SignatureType=2)")
	}
	e.logSafeOwnerMatch(ctx, safeAddress, common.HexToAddress(e.signerAddress))

	deployed, err := e.relayerGetDeployed(ctx, safeAddress.Hex())
	if err != nil {
		return fmt.Errorf("failed to check safe deployment: %w", err)
	}
	if !deployed {
		if err := e.deploySafeWallet(ctx, safeAddress); err != nil {
			return err
		}
	}

	calls, err := e.buildApprovalCalls(missingUSDC, missingCTF)
	if err != nil {
		return err
	}
	if len(calls) == 0 {
		return nil
	}

	nonceStr, err := e.relayerGetNonce(ctx, e.signerAddress, "SAFE")
	if err != nil {
		return fmt.Errorf("failed to get safe nonce: %w", err)
	}
	nonce, ok := new(big.Int).SetString(nonceStr, 10)
	if !ok {
		return fmt.Errorf("invalid safe nonce: %s", nonceStr)
	}

	safeCalls := make([]relayerSafeCall, 0, len(calls))
	for _, call := range calls {
		safeCalls = append(safeCalls, relayerSafeCall{
			Operation: 0,
			To:        call.To,
			Value:     call.Value,
			Data:      call.Data,
		})
	}

	var tx relayerSafeCall
	if len(safeCalls) == 1 {
		tx = safeCalls[0]
	} else {
		multiSendAddr := common.HexToAddress(e.config.RelayerSafeMultisend)
		multiSendData, err := encodeMultiSendData(safeCalls)
		if err != nil {
			return err
		}
		tx = relayerSafeCall{
			Operation: 1,
			To:        multiSendAddr,
			Value:     big.NewInt(0),
			Data:      multiSendData,
		}
	}

	chainID := big.NewInt(e.config.ChainID)
	digest := buildSafeTransactionDigest(
		chainID,
		safeAddress,
		tx,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		common.Address{},
		common.Address{},
		nonce,
	)
	sig, err := signPersonalHash(e.privateKey, digest)
	if err != nil {
		return fmt.Errorf("failed to sign safe approval: %w", err)
	}
	packedSig, err := packSafeSignature(sig)
	if err != nil {
		return fmt.Errorf("failed to pack safe signature: %w", err)
	}

	request := relayerTransactionRequest{
		Type:        "SAFE",
		From:        e.signerAddress,
		To:          tx.To.Hex(),
		ProxyWallet: safeAddress.Hex(),
		Data:        hexutil.Encode(tx.Data),
		Nonce:       nonceStr,
		Signature:   packedSig,
		SignatureParams: relayerSafeSignatureParams{
			GasPrice:       "0",
			Operation:      strconv.Itoa(int(tx.Operation)),
			SafeTxnGas:     "0",
			BaseGas:        "0",
			GasToken:       common.Address{}.Hex(),
			RefundReceiver: common.Address{}.Hex(),
		},
		Metadata: "polycatch approvals",
	}
	transactionID, err := e.relayerSubmit(ctx, request)
	if err != nil {
		return err
	}
	return e.waitForRelayerConfirmation(ctx, transactionID)
}

func (e *Executor) logSafeOwnerMatch(ctx context.Context, safeAddress common.Address, owner common.Address) {
	client, err := e.ensureRPCClient(ctx)
	if err != nil {
		log.Printf("WARNING | failed to verify safe owner (rpc): %v", err)
		return
	}
	code, err := client.CodeAt(ctx, safeAddress, nil)
	if err != nil {
		log.Printf("WARNING | failed to check safe code for %s: %v", safeAddress.Hex(), err)
		return
	}
	if len(code) == 0 {
		log.Printf("INFO | safe not deployed on-chain yet: %s", safeAddress.Hex())
		return
	}

	parsedABI, err := getSafeOwnersABI()
	if err != nil {
		log.Printf("WARNING | failed to parse safe owners ABI: %v", err)
		return
	}
	data, err := parsedABI.Pack("getOwners")
	if err != nil {
		log.Printf("WARNING | failed to pack getOwners call: %v", err)
		return
	}
	callMsg := ethereum.CallMsg{
		To:   &safeAddress,
		Data: data,
	}
	result, err := client.CallContract(ctx, callMsg, nil)
	if err != nil {
		log.Printf("WARNING | failed to call getOwners for %s: %v", safeAddress.Hex(), err)
		return
	}

	var owners []common.Address
	if err := parsedABI.UnpackIntoInterface(&owners, "getOwners", result); err != nil {
		log.Printf("WARNING | failed to unpack getOwners for %s: %v", safeAddress.Hex(), err)
		return
	}
	if len(owners) == 1 && owners[0] == owner {
		log.Printf("INFO | safe owner verified: safe=%s owner=%s", safeAddress.Hex(), owner.Hex())
		return
	}
	log.Printf(
		"WARNING | safe owner mismatch: safe=%s expected_owner=%s owners=%v",
		safeAddress.Hex(),
		owner.Hex(),
		addressesToStrings(owners),
	)
}

func (e *Executor) deploySafeWallet(ctx context.Context, safeAddress common.Address) error {
	chainID := big.NewInt(e.config.ChainID)
	factory := common.HexToAddress(e.config.RelayerSafeFactory)
	paymentToken := common.Address{}
	payment := big.NewInt(0)
	paymentReceiver := common.Address{}

	signature, err := buildSafeCreateSignature(
		e.privateKey,
		e.config.RelayerSafeFactoryName,
		chainID,
		factory,
		paymentToken,
		payment,
		paymentReceiver,
	)
	if err != nil {
		return err
	}

	request := relayerTransactionRequest{
		Type:        "SAFE_CREATE",
		From:        e.signerAddress,
		To:          factory.Hex(),
		ProxyWallet: safeAddress.Hex(),
		Data:        "0x",
		Signature:   signature,
		SignatureParams: map[string]string{
			"paymentToken":    paymentToken.Hex(),
			"payment":         payment.String(),
			"paymentReceiver": paymentReceiver.Hex(),
		},
		Metadata: "polycatch safe deploy",
	}

	transactionID, err := e.relayerSubmit(ctx, request)
	if err != nil {
		return err
	}
	return e.waitForRelayerConfirmation(ctx, transactionID)
}

type approvalCall struct {
	To    common.Address
	Value *big.Int
	Data  []byte
}

func (e *Executor) buildApprovalCalls(
	missingUSDC []common.Address,
	missingCTF []common.Address,
) ([]approvalCall, error) {
	var calls []approvalCall
	for _, spender := range missingUSDC {
		data, err := e.packERC20ApproveData(spender, maxUint256())
		if err != nil {
			return nil, err
		}
		calls = append(calls, approvalCall{
			To:    common.HexToAddress(e.config.USDCContract),
			Value: big.NewInt(0),
			Data:  data,
		})
	}
	for _, operator := range missingCTF {
		data, err := e.packERC1155ApprovalData(operator)
		if err != nil {
			return nil, err
		}
		calls = append(calls, approvalCall{
			To:    common.HexToAddress(e.config.CTFContract),
			Value: big.NewInt(0),
			Data:  data,
		})
	}
	return calls, nil
}

func (e *Executor) packERC20ApproveData(spender common.Address, amount *big.Int) ([]byte, error) {
	parsedABI, err := getERC20AllowanceABI()
	if err != nil {
		return nil, fmt.Errorf("failed to parse ERC20 ABI: %w", err)
	}
	data, err := parsedABI.Pack("approve", spender, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to pack approve call: %w", err)
	}
	return data, nil
}

func (e *Executor) packERC1155ApprovalData(operator common.Address) ([]byte, error) {
	parsedABI, err := getERC1155ApprovalABI()
	if err != nil {
		return nil, fmt.Errorf("failed to parse ERC1155 ABI: %w", err)
	}
	data, err := parsedABI.Pack("setApprovalForAll", operator, true)
	if err != nil {
		return nil, fmt.Errorf("failed to pack setApprovalForAll call: %w", err)
	}
	return data, nil
}

func (e *Executor) findMissingApprovals(
	ctx context.Context,
	signal *types.TradeSignal,
	maker common.Address,
	makerAmount *big.Int,
) ([]common.Address, []common.Address, error) {
	if makerAmount.Sign() <= 0 {
		return nil, nil, errors.New("maker amount must be greater than 0")
	}

	var missingUSDC []common.Address
	var missingCTF []common.Address

	if signal.Side == types.OrderSideBuy {
		spenders := e.requiredUSDCSpenders(signal.NegRisk)
		for _, spender := range spenders {
			allowance, err := e.CheckUSDCAllowance(ctx, maker, spender)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to check USDC allowance for %s: %w", spender.Hex(), err)
			}
			if allowance.Cmp(makerAmount) < 0 {
				missingUSDC = append(missingUSDC, spender)
			}
		}
	}

	if signal.Side == types.OrderSideSell {
		operators := e.requiredCTFOperators(signal.NegRisk)
		for _, operator := range operators {
			approved, err := e.CheckCTFApproval(ctx, maker, operator)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to check CTF approval for %s: %w", operator.Hex(), err)
			}
			if !approved {
				missingCTF = append(missingCTF, operator)
			}
		}
	}

	return missingUSDC, missingCTF, nil
}

func (e *Executor) requiredUSDCSpenders(negRisk bool) []common.Address {
	spenders := []common.Address{
		common.HexToAddress(e.config.CTFContract),
		common.HexToAddress(e.config.CTFExchange),
	}
	if negRisk {
		spenders = append(spenders,
			common.HexToAddress(e.config.NegRiskCTFExchange),
			common.HexToAddress(e.config.NegRiskAdapter),
		)
	}
	return spenders
}

func (e *Executor) requiredCTFOperators(negRisk bool) []common.Address {
	operators := []common.Address{
		common.HexToAddress(e.config.CTFExchange),
	}
	if negRisk {
		operators = append(operators,
			common.HexToAddress(e.config.NegRiskCTFExchange),
			common.HexToAddress(e.config.NegRiskAdapter),
		)
	}
	return operators
}

func (e *Executor) waitForTxReceipt(ctx context.Context, txHash common.Hash) error {
	client, err := e.ensureRPCClient(ctx)
	if err != nil {
		return err
	}

	timeout := time.NewTimer(60 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer timeout.Stop()
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return errors.New("timed out waiting for transaction receipt")
		case <-ticker.C:
			receipt, err := client.TransactionReceipt(ctx, txHash)
			if err != nil {
				continue
			}
			if receipt.Status != 1 {
				return fmt.Errorf("transaction reverted (status=%d)", receipt.Status)
			}
			return nil
		}
	}
}

func addressesToStrings(addrs []common.Address) []string {
	if len(addrs) == 0 {
		return nil
	}
	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		result = append(result, addr.Hex())
	}
	return result
}

// GetCurrentPrice fetches the current SELL price for a token (for cashing out positions)
func (e *Executor) GetCurrentPrice(ctx context.Context, tokenID string) (float64, error) {
	priceStr, err := e.getCurrentPrice(ctx, tokenID, types.OrderSideSell)
	if err != nil {
		return 0, err
	}
	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse price %q: %w", priceStr, err)
	}
	return price, nil
}

// getCurrentPrice fetches the current market price for a token using CLOB API
// side is required because prices differ for BUY vs SELL orders
// Uses L2 authentication for authenticated requests
func (e *Executor) getCurrentPrice(ctx context.Context, tokenID string, side types.OrderSide) (string, error) {
	// Check cache first (short TTL: 2 seconds)
	cacheKey := cache.PriceKey(tokenID, string(side))
	if price, ok := e.priceCache.Get(cacheKey); ok {
		return price, nil
	}

	// Use CLOB API to get current price (requires side parameter)
	path := fmt.Sprintf("/price?token_id=%s&side=%s", tokenID, string(side))
	url := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: timestamp + method + path + body (body is empty for GET)
	// Per official Polymarket client: format!("{timestamp}{method}{path}{body}")
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	// Generate HMAC-SHA256 signature
	secretBytes := decodeBuilderSecret(apiSecret)
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	// Encode signature using base64 URL-safe encoding (per official client)
	hmacSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Set L2 authentication headers
	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_SIGNATURE", hmacSignature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var priceResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &priceResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract price (adjust based on actual API response structure)
	price, ok := priceResponse["price"].(string)
	if !ok {
		if priceFloat, ok := priceResponse["price"].(float64); ok {
			price = fmt.Sprintf("%.6f", priceFloat)
		} else {
			return "", fmt.Errorf("price not found in response: %s", string(bodyBytes))
		}
	}

	// Cache the price (2 second TTL)
	e.priceCache.Set(cacheKey, price)

	return price, nil
}

type balanceAllowanceResponse struct {
	Balance   string `json:"balance"`
	Allowance string `json:"allowance"`
}

type tickSizeResponse struct {
	MinimumTickSize any `json:"minimum_tick_size"`
}

type roundConfig struct {
	priceDecimals  int
	sizeDecimals   int
	amountDecimals int
}

func roundConfigForTickSize(tickSize string) (roundConfig, error) {
	// Tick-size based rounding config (from Polymarket clob-client ROUNDING_CONFIG):
	// - priceDecimals: precision for price
	// - sizeDecimals: precision for shares sizing
	// - amountDecimals: precision for quote amounts (USDC) for limit order pricing math
	//
	// NOTE: Additional API restrictions exist for *market* orders (FAK/FOK),
	// enforced separately when computing amounts.
	switch tickSize {
	case "0.1":
		return roundConfig{priceDecimals: 1, sizeDecimals: 2, amountDecimals: 3}, nil
	case "0.01":
		return roundConfig{priceDecimals: 2, sizeDecimals: 2, amountDecimals: 4}, nil
	case "0.001":
		return roundConfig{priceDecimals: 3, sizeDecimals: 2, amountDecimals: 5}, nil
	case "0.0001":
		return roundConfig{priceDecimals: 4, sizeDecimals: 2, amountDecimals: 6}, nil
	default:
		return roundConfig{}, fmt.Errorf("unsupported tick size %q", tickSize)
	}
}

func computeOrderMicroAmounts(
	rc roundConfig,
	orderType string,
	price string,
	amountUSDCMicro int64,
) (usdcMicroRounded int64, sharesMicroRounded int64, err error) {
	if amountUSDCMicro <= 0 {
		return 0, 0, fmt.Errorf("trade amount must be > 0 (got %d micro-USDC)", amountUSDCMicro)
	}

	upperOrderType := strings.ToUpper(strings.TrimSpace(orderType))
	isMarketOrder := upperOrderType == "FAK" || upperOrderType == "FOK"

	// Use exact rationals to avoid float drift.
	priceRat, ok := new(big.Rat).SetString(price)
	if !ok {
		return 0, 0, fmt.Errorf("failed to parse price %q as rational", price)
	}
	if priceRat.Sign() <= 0 {
		return 0, 0, fmt.Errorf("price must be > 0 (got %q)", price)
	}
	rawPrice := roundRatNormal(priceRat, rc.priceDecimals)

	// amountUSD = amountUSDCMicro / 1e6
	amountUSD := new(big.Rat).Quo(new(big.Rat).SetInt64(amountUSDCMicro), new(big.Rat).SetInt64(1_000_000))

	// shares = amountUSD / rawPrice, then round DOWN to sizeDecimals (typically 2)
	shares := new(big.Rat).Quo(amountUSD, rawPrice)
	sharesRounded := roundRatDown(shares, rc.sizeDecimals)

	// makerUSD = sharesRounded * rawPrice, then round DOWN to USDC decimals.
	//
	// Polymarket's API has additional restrictions:
	// - Market orders (FAK/FOK): quote (USDC) must be <= 2 decimals
	// - Limit orders (GTC/GTD): quote (USDC) is more precise, but API appears to cap at 4 decimals
	const marketOrderUSDDecimals = 2
	const limitOrderUSDMaxDecimals = 4

	usdcDecimals := rc.amountDecimals
	if isMarketOrder {
		usdcDecimals = marketOrderUSDDecimals
	} else if usdcDecimals > limitOrderUSDMaxDecimals {
		usdcDecimals = limitOrderUSDMaxDecimals
	}

	makerUSD := new(big.Rat).Mul(sharesRounded, rawPrice)
	makerUSDRounded := roundRatDown(makerUSD, usdcDecimals)

	sharesMicroStr, err := ratToMicroString(sharesRounded)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to convert shares to micro units: %w", err)
	}
	makerMicroStr, err := ratToMicroString(makerUSDRounded)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to convert maker amount to micro units: %w", err)
	}

	sharesMicroRounded, err = strconv.ParseInt(sharesMicroStr, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse shares micro amount %q: %w", sharesMicroStr, err)
	}
	usdcMicroRounded, err = strconv.ParseInt(makerMicroStr, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse maker micro amount %q: %w", makerMicroStr, err)
	}

	// Validate amounts meet precision requirements before signing
	if err := validateAmountPrecision(usdcMicroRounded, usdcDecimals, "USDC"); err != nil {
		return 0, 0, fmt.Errorf("amount precision error: %w", err)
	}
	if err := validateAmountPrecision(sharesMicroRounded, rc.sizeDecimals, "shares"); err != nil {
		return 0, 0, fmt.Errorf("shares precision error: %w", err)
	}

	return usdcMicroRounded, sharesMicroRounded, nil
}

func computeOrderMicroAmountsFromShares(
	rc roundConfig,
	orderType string,
	price string,
	sharesMicro int64,
) (usdcMicroRounded int64, sharesMicroRounded int64, err error) {
	if sharesMicro <= 0 {
		return 0, 0, fmt.Errorf("share amount must be > 0 (got %d micro-shares)", sharesMicro)
	}

	upperOrderType := strings.ToUpper(strings.TrimSpace(orderType))
	isMarketOrder := upperOrderType == "FAK" || upperOrderType == "FOK"

	priceRat, ok := new(big.Rat).SetString(price)
	if !ok {
		return 0, 0, fmt.Errorf("failed to parse price %q as rational", price)
	}
	if priceRat.Sign() <= 0 {
		return 0, 0, fmt.Errorf("price must be > 0 (got %q)", price)
	}
	rawPrice := roundRatNormal(priceRat, rc.priceDecimals)

	// shares = sharesMicro / 1e6
	shares := new(big.Rat).Quo(new(big.Rat).SetInt64(sharesMicro), new(big.Rat).SetInt64(1_000_000))
	sharesRounded := roundRatDown(shares, rc.sizeDecimals)

	const marketOrderUSDDecimals = 2
	const limitOrderUSDMaxDecimals = 4

	usdcDecimals := rc.amountDecimals
	if isMarketOrder {
		usdcDecimals = marketOrderUSDDecimals
	} else if usdcDecimals > limitOrderUSDMaxDecimals {
		usdcDecimals = limitOrderUSDMaxDecimals
	}

	makerUSD := new(big.Rat).Mul(sharesRounded, rawPrice)
	makerUSDRounded := roundRatDown(makerUSD, usdcDecimals)

	sharesMicroStr, err := ratToMicroString(sharesRounded)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to convert shares to micro units: %w", err)
	}
	makerMicroStr, err := ratToMicroString(makerUSDRounded)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to convert maker amount to micro units: %w", err)
	}

	sharesMicroRounded, err = strconv.ParseInt(sharesMicroStr, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse shares micro amount %q: %w", sharesMicroStr, err)
	}
	usdcMicroRounded, err = strconv.ParseInt(makerMicroStr, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse maker micro amount %q: %w", makerMicroStr, err)
	}

	if err := validateAmountPrecision(usdcMicroRounded, usdcDecimals, "USDC"); err != nil {
		return 0, 0, fmt.Errorf("amount precision error: %w", err)
	}
	if err := validateAmountPrecision(sharesMicroRounded, rc.sizeDecimals, "shares"); err != nil {
		return 0, 0, fmt.Errorf("shares precision error: %w", err)
	}

	return usdcMicroRounded, sharesMicroRounded, nil
}

func pow10Int(n int) *big.Int {
	if n < 0 {
		return big.NewInt(0)
	}
	out := big.NewInt(1)
	ten := big.NewInt(10)
	for i := 0; i < n; i++ {
		out.Mul(out, ten)
	}
	return out
}

func roundRatDown(x *big.Rat, decimals int) *big.Rat {
	scale := new(big.Int).Set(pow10Int(decimals))
	scaled := new(big.Rat).Mul(x, new(big.Rat).SetInt(scale))
	q := new(big.Int).Quo(scaled.Num(), scaled.Denom())
	return new(big.Rat).Quo(new(big.Rat).SetInt(q), new(big.Rat).SetInt(scale))
}

// validateAmountPrecision checks that a micro-amount doesn't exceed the allowed decimal precision
// For example, if maxDecimals=2, then micro-amount must be divisible by 10000 (6-2=4 zeros)
func validateAmountPrecision(microAmount int64, maxDecimals int, label string) error {
	// micro-amounts have 6 decimal places, so we need (6 - maxDecimals) trailing zeros
	requiredZeros := 6 - maxDecimals
	if requiredZeros < 0 {
		requiredZeros = 0
	}
	divisor := int64(1)
	for i := 0; i < requiredZeros; i++ {
		divisor *= 10
	}
	if microAmount%divisor != 0 {
		return fmt.Errorf("%s amount %d has more than %d decimals (must be divisible by %d)", label, microAmount, maxDecimals, divisor)
	}
	return nil
}

func roundRatNormal(x *big.Rat, decimals int) *big.Rat {
	// Round half away from zero.
	scale := new(big.Int).Set(pow10Int(decimals))
	scaled := new(big.Rat).Mul(x, new(big.Rat).SetInt(scale))
	num := new(big.Int).Set(scaled.Num())
	den := new(big.Int).Set(scaled.Denom())

	quo, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	if rem.Sign() == 0 {
		return new(big.Rat).Quo(new(big.Rat).SetInt(quo), new(big.Rat).SetInt(scale))
	}

	// Compare 2*rem with den
	twoRem := new(big.Int).Mul(rem.Abs(rem), big.NewInt(2))
	cmp := twoRem.Cmp(den.Abs(den))

	rounded := new(big.Int).Set(quo)
	if cmp >= 0 {
		if num.Sign() >= 0 {
			rounded.Add(rounded, big.NewInt(1))
		} else {
			rounded.Sub(rounded, big.NewInt(1))
		}
	}
	return new(big.Rat).Quo(new(big.Rat).SetInt(rounded), new(big.Rat).SetInt(scale))
}

func ratToMicroString(x *big.Rat) (string, error) {
	// Convert a decimal USD/shares amount into 6-decimal micro units string.
	scaled := new(big.Rat).Mul(x, new(big.Rat).SetInt(big.NewInt(1_000_000)))
	if scaled.Denom().Cmp(big.NewInt(1)) != 0 {
		// We expect amounts to have been rounded such that micro-units are integral.
		return "", fmt.Errorf("amount has more than 6 decimals: %s", x.FloatString(12))
	}
	return scaled.Num().String(), nil
}

func (e *Executor) getTickSize(ctx context.Context, tokenID string) (string, error) {
	// Check cache first
	if meta, ok := e.tokenCache.Get(tokenID); ok && meta.TickSize != "" {
		return meta.TickSize, nil
	}

	path := fmt.Sprintf("/tick-size?token_id=%s", tokenID)
	url := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create tick-size request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute tick-size request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read tick-size response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tick-size API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var res tickSizeResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return "", fmt.Errorf("failed to parse tick-size response: %w", err)
	}

	var tickSize string
	switch v := res.MinimumTickSize.(type) {
	case string:
		tickSize = strings.TrimSpace(v)
	case float64:
		// JSON numbers decode as float64 in map/any.
		tickSize = strings.TrimSpace(strconv.FormatFloat(v, 'f', -1, 64))
	default:
		return "", fmt.Errorf("tick-size response has unsupported minimum_tick_size type %T: %s", v, string(bodyBytes))
	}

	if tickSize == "" {
		return "", fmt.Errorf("tick-size response missing minimum_tick_size: %s", string(bodyBytes))
	}

	// Update cache
	e.updateTokenCache(tokenID, func(m *cache.TokenMetadata) { m.TickSize = tickSize })

	return tickSize, nil
}

// updateTokenCache updates a field in the token metadata cache
func (e *Executor) updateTokenCache(tokenID string, update func(*cache.TokenMetadata)) {
	meta, ok := e.tokenCache.Get(tokenID)
	if !ok {
		meta = &cache.TokenMetadata{}
	}
	update(meta)
	e.tokenCache.Set(tokenID, meta)
}

// getMinOrderSize fetches the minimum order size (in shares) for a market from the order book summary.
func (e *Executor) getMinOrderSize(ctx context.Context, tokenID string) (float64, error) {
	// Check cache first
	if meta, ok := e.tokenCache.Get(tokenID); ok && meta.MinOrderSize > 0 {
		return meta.MinOrderSize, nil
	}

	url := fmt.Sprintf("%s/book?token_id=%s", e.config.CLOBAPIURL, tokenID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create book request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute book request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read book response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("book API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var res struct {
		MinOrderSize any `json:"min_order_size"`
	}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return 0, fmt.Errorf("failed to parse book response: %w", err)
	}

	var minOrderSize float64
	switch v := res.MinOrderSize.(type) {
	case string:
		minOrderSize, err = strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			minOrderSize = 5.0
		}
	case float64:
		minOrderSize = v
	default:
		// Default to 5 shares if not found (common Polymarket minimum)
		minOrderSize = 5.0
	}

	// Update cache
	e.updateTokenCache(tokenID, func(m *cache.TokenMetadata) { m.MinOrderSize = minOrderSize })

	return minOrderSize, nil
}

// GetCollateralBalanceAllowance fetches the user's collateral (USDC) balance + allowance from CLOB.
// Uses L2 authentication.
func (e *Executor) GetCollateralBalanceAllowance(ctx context.Context) (*big.Int, *big.Int, error) {
	path := fmt.Sprintf("/balance-allowance?asset_type=COLLATERAL&signature_type=%d", e.config.SignatureType)
	url := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create balance-allowance request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: timestamp + method + path + body (body is empty for GET)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes := decodeBuilderSecret(apiSecret)
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	hmacSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_SIGNATURE", hmacSignature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute balance-allowance request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read balance-allowance response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("balance-allowance API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var res balanceAllowanceResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, nil, fmt.Errorf("failed to parse balance-allowance response: %w", err)
	}

	bal, ok := new(big.Int).SetString(res.Balance, 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid balance %q in balance-allowance response: %s", res.Balance, string(bodyBytes))
	}
	allow, ok := new(big.Int).SetString(res.Allowance, 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid allowance %q in balance-allowance response: %s", res.Allowance, string(bodyBytes))
	}

	return bal, allow, nil
}

// getNegRisk fetches whether a market is NegRisk (multi-outcome) from CLOB API
// Uses public endpoint /neg-risk?token_id=...
func (e *Executor) getNegRisk(ctx context.Context, tokenID string) (bool, error) {
	// Check cache first - use NegRiskFetched flag since NegRisk bool default is false
	if meta, ok := e.tokenCache.Get(tokenID); ok && meta.NegRiskFetched {
		return meta.NegRisk, nil
	}

	url := fmt.Sprintf("%s/neg-risk?token_id=%s", e.config.CLOBAPIURL, tokenID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create neg-risk request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to execute neg-risk request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read neg-risk response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("neg-risk API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var res struct {
		NegRisk bool `json:"neg_risk"`
	}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return false, fmt.Errorf("failed to parse neg-risk response: %w", err)
	}

	// Update cache with both the value and the fetched flag
	e.updateTokenCache(tokenID, func(m *cache.TokenMetadata) {
		m.NegRisk = res.NegRisk
		m.NegRiskFetched = true
	})

	return res.NegRisk, nil
}

// getFeeRate fetches the fee rate for a token from the CLOB API
// Returns fee rate in basis points (e.g., 1000 = 10%)
func (e *Executor) getFeeRate(ctx context.Context, tokenID string) (string, error) {
	// Check cache first
	if meta, ok := e.tokenCache.Get(tokenID); ok && meta.FeeRateBps != "" {
		return meta.FeeRateBps, nil
	}

	url := fmt.Sprintf("%s/fee-rate?token_id=%s", e.config.CLOBAPIURL, tokenID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create fee-rate request: %w", err)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute fee-rate request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read fee-rate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fee-rate API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var raw map[string]any
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return "", fmt.Errorf("failed to parse fee-rate response: %w", err)
	}

	// Observed fee-rate response variants:
	// - {"fee_rate_bps": 1000}
	// - {"feeRateBps": 1000}
	// - {"base_fee": 1000}
	// Treat all as basis points.
	val, ok := raw["fee_rate_bps"]
	if !ok {
		val, ok = raw["feeRateBps"]
	}
	if !ok {
		val, ok = raw["base_fee"]
	}
	if !ok {
		val, ok = raw["baseFee"]
	}
	if !ok {
		return "", fmt.Errorf("fee-rate response missing fee_rate_bps/feeRateBps/base_fee/baseFee: %s", string(bodyBytes))
	}

	var feeRateBps string
	switch v := val.(type) {
	case float64:
		if v != float64(int64(v)) {
			return "", fmt.Errorf("fee-rate bps is not an integer (got %v) in response: %s", v, string(bodyBytes))
		}
		fee := int64(v)
		if fee < 0 {
			return "", fmt.Errorf("fee-rate bps must be >= 0 (got %d) in response: %s", fee, string(bodyBytes))
		}
		feeRateBps = fmt.Sprintf("%d", fee)
	case string:
		parsed, ok := new(big.Int).SetString(v, 10)
		if !ok {
			return "", fmt.Errorf("fee-rate bps is not a valid integer string (got %q) in response: %s", v, string(bodyBytes))
		}
		if parsed.Sign() < 0 {
			return "", fmt.Errorf("fee-rate bps must be >= 0 (got %s) in response: %s", parsed.String(), string(bodyBytes))
		}
		feeRateBps = parsed.String()
	default:
		return "", fmt.Errorf("fee-rate bps has unsupported type %T in response: %s", val, string(bodyBytes))
	}

	// Update cache
	e.updateTokenCache(tokenID, func(m *cache.TokenMetadata) { m.FeeRateBps = feeRateBps })
	log.Printf("DEBUG | Fee rate for token %s: %s bps (cached)", tokenID, feeRateBps)

	return feeRateBps, nil
}

// OpenOrder represents an open order from Polymarket CLOB API
type OpenOrder struct {
	OrderID     string `json:"orderID"`
	TokenID     string `json:"tokenId"`
	Side        string `json:"side"` // "BUY" or "SELL"
	Price       string `json:"price"`
	MakerAmount string `json:"makerAmount"`
	TakerAmount string `json:"takerAmount"`
	OrderType   string `json:"orderType"` // "FAK", "FOK", "GTC", "GTD"
	Status      string `json:"status"`    // "OPEN", "FILLED", "CANCELLED", etc.
	CreatedAt   string `json:"createdAt"`
	MarketTitle string `json:"marketTitle,omitempty"` // Not in API, we'll fetch separately
	Outcome     string `json:"outcome,omitempty"`     // Not in API, we'll fetch separately
}

// ActiveOrder represents an open/pending order (resting on the book) from CLOB /data/orders.
// Fields match Polymarket clob-client OpenOrder schema.
type ActiveOrder struct {
	ID              string   `json:"id"`
	Status          string   `json:"status"`
	Owner           string   `json:"owner"`
	MakerAddress    string   `json:"maker_address"`
	Market          string   `json:"market"`
	AssetID         string   `json:"asset_id"`
	Side            string   `json:"side"` // "BUY" or "SELL"
	OriginalSize    string   `json:"original_size"`
	SizeMatched     string   `json:"size_matched"`
	Price           string   `json:"price"`
	AssociateTrades []string `json:"associate_trades"`
	Outcome         string   `json:"outcome"`
	CreatedAt       int64    `json:"created_at"` // seconds
	Expiration      string   `json:"expiration"`
	OrderType       string   `json:"order_type"` // "FAK", "FOK", "GTC", "GTD"
}

// GetOpenOrders fetches open orders for the authenticated user from CLOB API
func (e *Executor) GetOpenOrders(ctx context.Context) ([]*OpenOrder, error) {
	path := "/orders"
	url := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create orders request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes := decodeBuilderSecret(apiSecret)

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)
	req.Header.Set("POLY_SIGNATURE", signature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute orders request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read orders response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("orders API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var orders []*OpenOrder
	if err := json.Unmarshal(bodyBytes, &orders); err != nil {
		// Try parsing as object with orders array
		var response struct {
			Orders []*OpenOrder `json:"orders"`
		}
		if err2 := json.Unmarshal(bodyBytes, &response); err2 != nil {
			return nil, fmt.Errorf("failed to parse orders response: %w (body: %s)", err, string(bodyBytes))
		}
		orders = response.Orders
	}

	// Filter only OPEN orders
	var openOrders []*OpenOrder
	for _, order := range orders {
		if strings.ToUpper(order.Status) == "OPEN" {
			openOrders = append(openOrders, order)
		}
	}

	return openOrders, nil
}

// GetActiveOrders fetches open/pending orders for the authenticated user from CLOB API.
// Uses: GET /data/orders (aka "open orders" in clob-client).
// Optional filters: id, market, asset_id.
func (e *Executor) GetActiveOrders(ctx context.Context, id string, market string, assetID string) ([]*ActiveOrder, error) {
	q := url.Values{}
	if strings.TrimSpace(id) != "" {
		q.Set("id", strings.TrimSpace(id))
	}
	if strings.TrimSpace(market) != "" {
		q.Set("market", strings.TrimSpace(market))
	}
	if strings.TrimSpace(assetID) != "" {
		q.Set("asset_id", strings.TrimSpace(assetID))
	}

	path := "/data/orders"
	if enc := q.Encode(); enc != "" {
		path = path + "?" + enc
	}
	fullURL := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create orders request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes := decodeBuilderSecret(apiSecret)

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	// Must be URL-safe base64 encoding (keep '=' suffix) to match official clob-client.
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Official client includes POLY_ADDRESS in L2 headers.
	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)
	req.Header.Set("POLY_SIGNATURE", signature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute orders request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read orders response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("orders API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var orders []*ActiveOrder
	if err := json.Unmarshal(bodyBytes, &orders); err == nil {
		return orders, nil
	}

	// Some endpoints return {data: [...], next_cursor: ...}; tolerate that too.
	var wrapped struct {
		Data []*ActiveOrder `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &wrapped); err != nil {
		return nil, fmt.Errorf("failed to parse orders response: %w (body: %s)", err, string(bodyBytes))
	}
	return wrapped.Data, nil
}

// CancelOrder cancels an open order by order ID
func (e *Executor) CancelOrder(ctx context.Context, orderID string) error {
	path := "/order"
	fullURL := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	payload := struct {
		OrderID string `json:"orderID"`
	}{
		OrderID: orderID,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal cancel order payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", fullURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create cancel order request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s%s", timestamp, "DELETE", path, string(bodyBytes))

	secretBytes := decodeBuilderSecret(apiSecret)

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Official client includes POLY_ADDRESS in L2 headers.
	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)
	req.Header.Set("POLY_SIGNATURE", signature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute cancel order request: %w", err)
	}
	defer resp.Body.Close()

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read cancel order response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("cancel order API returned status %d: %s", resp.StatusCode, string(respBodyBytes))
	}

	log.Printf("✅ Order %s cancelled successfully", orderID)
	return nil
}

// Trade represents a completed trade from Polymarket CLOB API
type Trade struct {
	TradeID       string  `json:"id"`
	TakerOrderID  string  `json:"taker_order_id"`
	TokenID       string  `json:"asset_id"`
	Side          string  `json:"side"` // "BUY" or "SELL"
	Price         float64 `json:"price,string"`
	Size          float64 `json:"size,string"`
	FeeRateBps    float64 `json:"fee_rate_bps,string"`
	Status        string  `json:"status"`
	MatchTime     string  `json:"match_time"`
	Outcome       string  `json:"outcome"`
	MarketTitle   string  `json:"-"` // Not in API
	TransactionID string  `json:"transaction_hash"`
}

// GetTradeHistory fetches trade history for the authenticated user
func (e *Executor) GetTradeHistory(ctx context.Context, limit int) ([]*Trade, error) {
	path := fmt.Sprintf("/trades?limit=%d", limit)
	url := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create trades request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.CLOBAPIKey)
	apiSecret := strings.TrimSpace(e.config.CLOBAPISecret)
	apiPassphrase := strings.TrimSpace(e.config.CLOBAPIPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes := decodeBuilderSecret(apiSecret)

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)
	req.Header.Set("POLY_SIGNATURE", signature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute trades request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read trades response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trades API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var trades []*Trade
	if err := json.Unmarshal(bodyBytes, &trades); err != nil {
		return nil, fmt.Errorf("failed to parse trades response: %w", err)
	}

	return trades, nil
}

// Position represents a user's position (shares held) in a market
// Fields match the Polymarket Data API /positions response
type Position struct {
	ProxyWallet     string  `json:"proxyWallet"`
	TokenID         string  `json:"asset"`
	ConditionID     string  `json:"conditionId"`
	Size            float64 `json:"size"`         // Number of shares
	AvgPrice        float64 `json:"avgPrice"`     // Average entry price
	InitialValue    float64 `json:"initialValue"` // Cost basis
	CurrentValue    float64 `json:"currentValue"` // Current market value
	CashPnL         float64 `json:"cashPnl"`      // Unrealized P&L in USD
	PercentPnL      float64 `json:"percentPnl"`   // Unrealized P&L in %
	TotalBought     float64 `json:"totalBought"`  // Total shares ever bought
	RealizedPnL     float64 `json:"realizedPnl"`  // Realized P&L
	PercentRealized float64 `json:"percentRealizedPnl"`
	CurrentPrice    float64 `json:"curPrice"`   // Current market price
	Redeemable      bool    `json:"redeemable"` // Can be redeemed (market resolved)
	Mergeable       bool    `json:"mergeable"`  // Can be merged
	Title           string  `json:"title"`      // Market title
	Slug            string  `json:"slug"`       // Market slug
	Icon            string  `json:"icon"`       // Market icon URL
	EventID         string  `json:"eventId"`
	EventSlug       string  `json:"eventSlug"`
	Outcome         string  `json:"outcome"` // "Yes", "No", "Up", "Down"
	OutcomeIndex    int     `json:"outcomeIndex"`
	OppositeOutcome string  `json:"oppositeOutcome"`
	OppositeAsset   string  `json:"oppositeAsset"`
	EndDate         string  `json:"endDate"`
	NegativeRisk    bool    `json:"negativeRisk"`
}

// dataAPIBaseURL is the Polymarket Data API base URL
const dataAPIBaseURL = "https://data-api.polymarket.com"

// GetPositions fetches user's current positions from Polymarket Data API
// Uses: https://data-api.polymarket.com/positions
func (e *Executor) GetPositions(ctx context.Context) ([]*Position, error) {
	// Use the funder address (proxy wallet) for position lookup
	// Query params: sizeThreshold=1 filters out dust, sortBy=TOKENS sorts by value
	url := fmt.Sprintf("%s/positions?user=%s&sizeThreshold=0.01&limit=100&sortBy=TOKENS&sortDirection=DESC",
		dataAPIBaseURL, e.config.FunderAddress)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create positions request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute positions request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read positions response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("positions API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var positions []*Position
	if err := json.Unmarshal(bodyBytes, &positions); err != nil {
		return nil, fmt.Errorf("failed to parse positions response: %w", err)
	}

	return positions, nil
}

// GetActivePositions fetches active (non-redeemable, non-mergeable) positions from Polymarket Data API.
// This is used for the Telegram /trade UI to show only currently tradable positions.
func (e *Executor) GetActivePositions(ctx context.Context) ([]*Position, error) {
	url := fmt.Sprintf(
		"%s/positions?user=%s&sizeThreshold=1&limit=100&sortBy=CURRENT&sortDirection=ASC&redeemable=false&mergeable=false",
		dataAPIBaseURL,
		e.config.FunderAddress,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create positions request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute positions request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read positions response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("positions API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var positions []*Position
	if err := json.Unmarshal(bodyBytes, &positions); err != nil {
		return nil, fmt.Errorf("failed to parse positions response: %w", err)
	}
	return positions, nil
}

// ClosedPosition represents a closed position from the Data API
// Fields match the Polymarket Data API /v1/closed-positions response
type ClosedPosition struct {
	ProxyWallet     string  `json:"proxyWallet"`
	TokenID         string  `json:"asset"`
	ConditionID     string  `json:"conditionId"`
	AvgPrice        float64 `json:"avgPrice"`    // Average entry price
	TotalBought     float64 `json:"totalBought"` // Total shares bought
	RealizedPnL     float64 `json:"realizedPnl"` // Profit/loss realized
	CurrentPrice    float64 `json:"curPrice"`    // Final price (usually 0 or 1)
	Title           string  `json:"title"`       // Market title
	Slug            string  `json:"slug"`        // Market slug
	Icon            string  `json:"icon"`        // Market icon URL
	EventSlug       string  `json:"eventSlug"`
	Outcome         string  `json:"outcome"` // "Yes", "No", "Up", "Down"
	OutcomeIndex    int     `json:"outcomeIndex"`
	OppositeOutcome string  `json:"oppositeOutcome"`
	OppositeAsset   string  `json:"oppositeAsset"`
	EndDate         string  `json:"endDate"`
	Timestamp       int64   `json:"timestamp"` // Unix timestamp when closed
}

// GetClosedPositions fetches user's closed positions from Polymarket Data API
// Uses: https://data-api.polymarket.com/v1/closed-positions
func (e *Executor) GetClosedPositions(ctx context.Context, limit int) ([]*ClosedPosition, error) {
	// sortBy=REALIZEDPNL shows most profitable/lossy trades first
	url := fmt.Sprintf("%s/v1/closed-positions?user=%s&limit=%d&sortBy=REALIZEDPNL&sortDirection=DESC",
		dataAPIBaseURL, e.config.FunderAddress, limit)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create closed-positions request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute closed-positions request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read closed-positions response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("closed-positions API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var closedPositions []*ClosedPosition
	if err := json.Unmarshal(bodyBytes, &closedPositions); err != nil {
		return nil, fmt.Errorf("failed to parse closed-positions response: %w", err)
	}

	return closedPositions, nil
}

// SellPosition places a SELL order to close/reduce a position
func (e *Executor) SellPosition(ctx context.Context, tokenID string, shares float64, price float64, orderType string, expirationUnix int64) (string, error) {
	// Build a trade signal for selling
	signal := &types.TradeSignal{
		TokenID:        tokenID,
		Side:           types.OrderSideSell,
		Price:          fmt.Sprintf("%.4f", price),
		Size:           fmt.Sprintf("%.0f", shares*1_000_000), // micro-shares
		SizeIsShares:   true,
		OrderType:      orderType,
		ExpirationUnix: expirationUnix,
		MaxSlippage:    0, // Disable slippage check for sell
	}

	return e.buildAndSubmitOrder(ctx, signal)
}
