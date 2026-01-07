package executor

import (
	"bufio"
	"context"
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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

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

// Executor executes trades based on trade signals from the Analyst
type Executor struct {
	config         *config.Config
	client         *ethclient.Client
	tradeSignalsCh <-chan *types.TradeSignal
	errorsCh       chan error
	stopCh         chan struct{}
	running        bool
	httpClient     *http.Client
	ipcReader      *ipc.Reader // IPC reader for receiving signals from monitor
	useIPC         bool        // Whether to use IPC instead of channel
	signerAddress  string      // Signer address derived from private key
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

	// Log credential status (without exposing values)
	log.Printf("Executor | API credentials loaded: Key=%d chars, Secret=%d chars, Passphrase=%d chars",
		len(strings.TrimSpace(cfg.BuilderAPIKey)),
		len(strings.TrimSpace(cfg.BuilderSecret)),
		len(strings.TrimSpace(cfg.BuilderPassphrase)))
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

// checkSlippage verifies that price hasn't moved beyond tolerance
func (e *Executor) checkSlippage(ctx context.Context, signal *types.TradeSignal) error {
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

	// Parse order size and price
	sizeFloat, err := strconv.ParseFloat(signal.Size, 64)
	if err != nil {
		return "", fmt.Errorf("invalid size: %w", err)
	}
	priceFloat, err := strconv.ParseFloat(signal.Price, 64)
	if err != nil {
		return "", fmt.Errorf("invalid price: %w", err)
	}

	// Calculate required USDC (size * price, in USDC units with 6 decimals)
	requiredAmount := big.NewInt(int64(sizeFloat * priceFloat * 1_000_000))

	// Calculate max usable balance (based on MaxTradePercent)
	maxUsableBalance := new(big.Int).Div(new(big.Int).Mul(balance, big.NewInt(int64(e.config.MaxTradePercent))), big.NewInt(100))

	// Convert to dollar amounts for logging
	balanceDollars := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(1_000_000))
	requiredDollars := new(big.Float).Quo(new(big.Float).SetInt(requiredAmount), big.NewFloat(1_000_000))
	balanceDollarStr, _ := balanceDollars.Float64()
	requiredDollarStr, _ := requiredDollars.Float64()

	// Check if balance is below minimum
	if balance.Cmp(e.config.MinTradeAmount) < 0 {
		balanceDollarStr, _ := balanceDollars.Float64()
		minTradeDollarStr, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
		return "", fmt.Errorf("insufficient balance: have $%.2f, need at least $%.2f (minimum trade amount)",
			balanceDollarStr, minTradeDollarStr)
	}

	// Interactive mode: prompt user for trade amount
	if e.config.InteractiveMode {
		userAmount, err := e.promptTradeAmount(balanceDollarStr, requiredDollarStr, priceFloat)
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

	// Auto-scaling mode: scale down if needed
	log.Printf("Balance: $%.2f | Required: $%.2f | Max usable: %d%%",
		balanceDollarStr, requiredDollarStr, e.config.MaxTradePercent)

	// If we have enough balance, use original size
	if maxUsableBalance.Cmp(requiredAmount) >= 0 {
		log.Printf("Balance check passed: sufficient funds available")
		return signal.Size, nil
	}

	// Scale down: calculate how many shares we can buy with available balance
	// shares = (available_balance / price) / 1_000_000
	priceInUSDC := big.NewInt(int64(priceFloat * 1_000_000))
	scaledShares := new(big.Int).Div(new(big.Int).Mul(maxUsableBalance, big.NewInt(1_000_000)), priceInUSDC)

	// Check minimum trade amount
	minTradeCost := new(big.Int).Mul(scaledShares, priceInUSDC)
	minTradeCost.Div(minTradeCost, big.NewInt(1_000_000))

	if minTradeCost.Cmp(e.config.MinTradeAmount) < 0 {
		minTradeCostDollars, _ := new(big.Float).Quo(new(big.Float).SetInt(minTradeCost), big.NewFloat(1_000_000)).Float64()
		minTradeAmountDollars, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
		return "", fmt.Errorf("scaled trade amount ($%.2f) below minimum ($%.2f)",
			minTradeCostDollars, minTradeAmountDollars)
	}

	scaledSize := scaledShares.String()
	scaledDollars := new(big.Float).Quo(new(big.Float).SetInt(minTradeCost), big.NewFloat(1_000_000))
	scaledDollarStr, _ := scaledDollars.Float64()

	log.Printf("Trade scaled down: Original: %s shares ($%.2f) → Scaled: %s shares ($%.2f)",
		signal.Size, requiredDollarStr, scaledSize, scaledDollarStr)

	return scaledSize, nil
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

// OrderData holds all the fields needed for order creation and signing
type OrderData struct {
	Salt          int64
	Maker         string
	Signer        string
	Taker         string
	TokenID       string
	MakerAmount   string
	TakerAmount   string
	Side          int // 0 = BUY, 1 = SELL
	Expiration    string
	Nonce         string
	FeeRateBps    string
	SignatureType int
}

// buildAndSubmitOrder builds order data, signs it, and submits to the API
func (e *Executor) buildAndSubmitOrder(ctx context.Context, signal *types.TradeSignal) (string, error) {
	// Parse price
	price, err := strconv.ParseFloat(signal.Price, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse price: %w", err)
	}

	// Parse size as the number of shares (already in micro-units)
	size, err := strconv.ParseInt(signal.Size, 10, 64)
	if err != nil {
		return "", fmt.Errorf("failed to parse size: %w", err)
	}

	// Calculate makerAmount and takerAmount based on side and price
	// For BUY: makerAmount = USDC you pay, takerAmount = shares you receive
	// For SELL: makerAmount = shares you sell, takerAmount = USDC you receive
	//
	// Polymarket precision requirements (varies by market tick size):
	// - USDC amounts: max 2 decimal places → multiples of 10,000 (since $0.01 = 10,000 micro-USDC)
	// - Share amounts: max 4 decimal places → multiples of 100 (since 0.0001 shares = 100 micro)
	var makerAmount, takerAmount int64
	var side int
	if signal.Side == types.OrderSideBuy {
		side = 0 // BUY
		// Calculate raw amounts
		rawTakerAmount := size
		rawMakerAmount := int64(float64(size) * price)

		// Round makerAmount (USDC) to 2 decimals (multiples of 10,000)
		makerAmount = (rawMakerAmount / 10000) * 10000
		// Round takerAmount (shares) to 4 decimals (multiples of 100)
		takerAmount = (rawTakerAmount / 100) * 100

		// Ensure amounts aren't zero
		if makerAmount == 0 {
			makerAmount = 10000 // Minimum $0.01
		}
		if takerAmount == 0 {
			takerAmount = 100 // Minimum shares
		}
	} else {
		side = 1 // SELL
		// Calculate raw amounts
		rawMakerAmount := size
		rawTakerAmount := int64(float64(size) * price)

		// Round makerAmount (shares) to 4 decimals (multiples of 100)
		makerAmount = (rawMakerAmount / 100) * 100
		// Round takerAmount (USDC) to 2 decimals (multiples of 10,000)
		takerAmount = (rawTakerAmount / 10000) * 10000

		// Ensure amounts aren't zero
		if makerAmount == 0 {
			makerAmount = 100
		}
		if takerAmount == 0 {
			takerAmount = 10000
		}
	}

	makerAmountStr := strconv.FormatInt(makerAmount, 10)
	takerAmountStr := strconv.FormatInt(takerAmount, 10)

	// Generate random salt within 2^32 range (matches Polymarket's official Go library)
	// This is critical - nanosecond timestamps are too large and cause JSON precision issues
	salt := generateRandomSalt()

	// Build order data
	orderData := &OrderData{
		Salt:          salt,
		Maker:         e.config.FunderAddress,
		Signer:        e.signerAddress,
		Taker:         "0x0000000000000000000000000000000000000000",
		TokenID:       signal.TokenID,
		MakerAmount:   makerAmountStr,
		TakerAmount:   takerAmountStr,
		Side:          side,
		Expiration:    "0",
		Nonce:         "0",
		FeeRateBps:    "0",
		SignatureType: e.config.SignatureType,
	}

	log.Printf("DEBUG | Order: side=%d, price=%.6f, size=%d, makerAmount=%s, takerAmount=%s",
		side, price, size, makerAmountStr, takerAmountStr)

	// Generate EIP-712 signature for this exact order data
	signature, err := e.signOrder(orderData)
	if err != nil {
		return "", fmt.Errorf("failed to sign order: %w", err)
	}

	// Submit order with signature
	return e.submitSignedOrder(ctx, signal, orderData, signature)
}

// CTF Exchange contract address on Polygon mainnet
const CTFExchangeAddress = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"

// signOrder generates an EIP-712 signature for the order
// Uses the CTF Exchange Order type hash from Polymarket
func (e *Executor) signOrder(order *OrderData) (string, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(e.config.SignerPrivateKey, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	// Order type hash: keccak256("Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType)")
	orderTypeHash := crypto.Keccak256([]byte("Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType)"))

	// Parse order fields
	salt := new(big.Int).SetInt64(order.Salt)
	maker := common.HexToAddress(order.Maker)
	signer := common.HexToAddress(order.Signer)
	taker := common.HexToAddress(order.Taker)
	tokenId := new(big.Int)
	tokenId.SetString(order.TokenID, 10)
	makerAmount := new(big.Int)
	makerAmount.SetString(order.MakerAmount, 10)
	takerAmount := new(big.Int)
	takerAmount.SetString(order.TakerAmount, 10)
	expiration := new(big.Int)
	expiration.SetString(order.Expiration, 10)
	nonce := new(big.Int)
	nonce.SetString(order.Nonce, 10)
	feeRateBps := new(big.Int)
	feeRateBps.SetString(order.FeeRateBps, 10)

	// Encode order struct - all fields padded to 32 bytes
	structData := []byte{}
	structData = append(structData, orderTypeHash...)
	structData = append(structData, common.LeftPadBytes(salt.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(maker.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(signer.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(taker.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(tokenId.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(makerAmount.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(takerAmount.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(expiration.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(nonce.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes(feeRateBps.Bytes(), 32)...)
	structData = append(structData, common.LeftPadBytes([]byte{uint8(order.Side)}, 32)...)
	structData = append(structData, common.LeftPadBytes([]byte{uint8(order.SignatureType)}, 32)...)

	structHash := crypto.Keccak256(structData)

	// EIP-712 domain separator WITH verifyingContract (CTF Exchange)
	// Domain type: "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	domainTypeHash := crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	nameHash := crypto.Keccak256([]byte("Polymarket CTF Exchange"))
	versionHash := crypto.Keccak256([]byte("1"))
	chainId := new(big.Int).SetInt64(e.config.ChainID)
	verifyingContract := common.HexToAddress(CTFExchangeAddress)

	domainData := []byte{}
	domainData = append(domainData, domainTypeHash...)
	domainData = append(domainData, nameHash...)
	domainData = append(domainData, versionHash...)
	domainData = append(domainData, common.LeftPadBytes(chainId.Bytes(), 32)...)
	domainData = append(domainData, common.LeftPadBytes(verifyingContract.Bytes(), 32)...)

	domainSeparator := crypto.Keccak256(domainData)

	// Final EIP-712 hash: keccak256("\x19\x01" + domainSeparator + structHash)
	finalData := []byte{0x19, 0x01}
	finalData = append(finalData, domainSeparator...)
	finalData = append(finalData, structHash...)
	hash := crypto.Keccak256(finalData)

	// Sign the hash
	sig, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// Adjust v value (27 or 28 for Ethereum)
	sig[64] += 27

	return hexutil.Encode(sig), nil
}

// submitSignedOrder submits a signed order to the CLOB API
func (e *Executor) submitSignedOrder(ctx context.Context, signal *types.TradeSignal, order *OrderData, signature string) (string, error) {
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)

	// Construct the signed order object
	// Note: salt must be sent as string to avoid JSON precision loss for large numbers
	signedOrder := map[string]interface{}{
		"salt":          order.Salt, // Number - safe now that we use random salt within 2^32
		"maker":         order.Maker,
		"signer":        order.Signer,
		"taker":         order.Taker,
		"tokenId":       order.TokenID,
		"makerAmount":   order.MakerAmount,
		"takerAmount":   order.TakerAmount,
		"side":          string(signal.Side), // API expects "BUY" or "SELL"
		"expiration":    order.Expiration,
		"nonce":         order.Nonce,
		"feeRateBps":    order.FeeRateBps,
		"signatureType": order.SignatureType,
		"signature":     signature,
	}

	// Construct full order payload
	orderPayload := map[string]interface{}{
		"deferExec": false,
		"order":     signedOrder,
		"owner":     apiKey,
		"orderType": "FAK",
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
	log.Printf("DEBUG | L2 Auth - Signature: %s", hmacSignature)

	// Log full payload for debugging
	log.Printf("DEBUG | Full payload:\n%s", string(payloadBytes))

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
		log.Printf("DEBUG | API Error Response:\n%s", string(bodyBytes))
		log.Printf("DEBUG | Request Payload was:\n%s", string(payloadBytes))

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

	// Extract order ID
	orderID, ok := orderResponse["orderId"].(string)
	if !ok {
		// Try alternative field names
		if id, ok := orderResponse["id"].(string); ok {
			orderID = id
		} else {
			return "", fmt.Errorf("order ID not found in response: %s", string(bodyBytes))
		}
	}

	return orderID, nil
}

// getCurrentPrice fetches the current market price for a token using CLOB API
// side is required because prices differ for BUY vs SELL orders
// Uses L2 authentication for authenticated requests
func (e *Executor) getCurrentPrice(ctx context.Context, tokenID string, side types.OrderSide) (string, error) {
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

	return price, nil
}
