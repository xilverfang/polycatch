package executor

import (
	"bufio"
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
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	// Official Polymarket order signing library
	"github.com/polymarket/go-order-utils/pkg/builder"
	"github.com/polymarket/go-order-utils/pkg/model"

	"github.com/polywatch/internal/cache"
	"github.com/polywatch/internal/config"
	"github.com/polywatch/internal/ipc"
	"github.com/polywatch/internal/types"
	"github.com/polywatch/internal/utils"
)

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

	// Validate Builder API credentials
	if strings.TrimSpace(cfg.BuilderAPIKey) == "" {
		return nil, errors.New("BUILDER_API_KEY is required and cannot be empty")
	}
	if strings.TrimSpace(cfg.BuilderSecret) == "" {
		return nil, errors.New("BUILDER_SECRET is required and cannot be empty")
	}
	if strings.TrimSpace(cfg.BuilderPassphrase) == "" {
		return nil, errors.New("BUILDER_PASSPHRASE is required and cannot be empty")
	}

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
	log.Printf("Executor | API credentials loaded: Key=%d chars, Secret=%d chars, Passphrase=%d chars",
		len(strings.TrimSpace(cfg.BuilderAPIKey)),
		len(strings.TrimSpace(cfg.BuilderSecret)),
		len(strings.TrimSpace(cfg.BuilderPassphrase)))
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

	// In Telegram execution, signal.Size is treated as an amount of USDC (micro-USDC, 6 decimals).
	// UserMonitor.ExecuteTrade enforces this by overwriting Size based on the user-selected USD amount.
	amountUSDCMicro, err := strconv.ParseInt(signal.Size, 10, 64)
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
	if amountUSDCMicro <= 0 {
		return "", fmt.Errorf("trade amount must be > 0 (got %d micro-USDC)", amountUSDCMicro)
	}

	tickSize, err := e.getTickSize(ctx, signal.TokenID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tick size for token %s: %w", signal.TokenID, err)
	}
	rc, err := roundConfigForTickSize(tickSize)
	if err != nil {
		return "", fmt.Errorf("failed to resolve rounding config for tick size %s (token %s): %w", tickSize, signal.TokenID, err)
	}

	usdcMicroRounded, sharesMicroRounded, err := computeOrderMicroAmounts(
		rc,
		orderType,
		signal.Price,
		amountUSDCMicro,
	)
	if err != nil {
		return "", fmt.Errorf("failed to compute order amounts: %w", err)
	}

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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)

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

	// Trim whitespace from credentials (common issue when copying from UI)
	// apiKey is already defined above for the owner field
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

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
	// Secret is base64 URL-safe encoded, decode it first
	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		// Try standard base64 if URL-safe fails
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			// If not base64, use as-is
			secretBytes = []byte(apiSecret)
		}
	}
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

		// Enhanced error message for 401 errors
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf("API returned 401 Unauthorized: %s\n"+
				"Troubleshooting:\n"+
				"1. Verify BUILDER_API_KEY matches the API key from Polymarket Builder Dashboard\n"+
				"2. Verify SIGNER_PRIVATE_KEY corresponds to the address used to create the API key\n"+
				"3. Verify BUILDER_SECRET and BUILDER_PASSPHRASE are correct\n"+
				"4. Ensure the API key was created using L1 authentication with the correct signer address\n"+
				"5. Check that POLY_ADDRESS (%s) matches the address used during API key creation",
				string(bodyBytes), e.signerAddress)
		}

		// Enhanced error for 400 errors
		if resp.StatusCode == http.StatusBadRequest {
			return "", fmt.Errorf("API returned 400 Bad Request: %s\n"+
				"Payload sent:\n%s",
				string(bodyBytes), string(payloadBytes))
		}

		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: timestamp + method + path + body (body is empty for GET)
	// Per official Polymarket client: format!("{timestamp}{method}{path}{body}")
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	// Generate HMAC-SHA256 signature
	// Secret is base64 URL-safe encoded, decode it first
	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		// Try standard base64 if URL-safe fails
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			// If not base64, use as-is
			secretBytes = []byte(apiSecret)
		}
	}
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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: timestamp + method + path + body (body is empty for GET)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			secretBytes = []byte(apiSecret)
		}
	}
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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			secretBytes = []byte(apiSecret)
		}
	}

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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			secretBytes = []byte(apiSecret)
		}
	}

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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s%s", timestamp, "DELETE", path, string(bodyBytes))

	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			secretBytes = []byte(apiSecret)
		}
	}

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
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", timestamp, "GET", path)

	secretBytes, decodeErr := base64.URLEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		secretBytes, decodeErr = base64.StdEncoding.DecodeString(apiSecret)
		if decodeErr != nil {
			secretBytes = []byte(apiSecret)
		}
	}

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
		OrderType:      orderType,
		ExpirationUnix: expirationUnix,
		MaxSlippage:    0, // Disable slippage check for sell
	}

	return e.buildAndSubmitOrder(ctx, signal)
}
