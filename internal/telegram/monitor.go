package telegram

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/polycatch/internal/analyst"
	"github.com/polycatch/internal/config"
	"github.com/polycatch/internal/executor"
	"github.com/polycatch/internal/types"
)

// Monitor limits - configurable via environment variables
var (
	// MaxConcurrentMonitors limits simultaneous monitoring sessions
	// Each monitor creates a websocket + API polling loop
	// Default: 50 (reasonable for most RPC providers)
	MaxConcurrentMonitors = getEnvInt("MAX_CONCURRENT_MONITORS", 50)

	// MonitorWarningThreshold triggers warnings when approaching limit
	MonitorWarningThreshold = getEnvInt("MONITOR_WARNING_THRESHOLD", 40)
)

// getEnvInt gets an int from environment variable or returns default
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			return i
		}
	}
	return defaultVal
}

// UserMonitor manages Polycatch instances for a single user
type UserMonitor struct {
	userID     int64
	chatID     int64
	depositsCh <-chan *types.Deposit // Receives from shared listener
	analyst    *analyst.Analyst
	executor   *executor.Executor
	ctx        context.Context
	cancel     context.CancelFunc
	bot        *Bot
	creds      *DecryptedCredentials
	isRunning  bool
	mu         sync.RWMutex
}

// MonitorManager manages all active user monitors
type MonitorManager struct {
	monitors       map[int64]*UserMonitor // userID -> monitor
	sharedListener *SharedListener        // Single websocket for all monitors
	mu             sync.RWMutex
	bot            *Bot
}

// NewMonitorManager creates a new monitor manager
func NewMonitorManager(bot *Bot) *MonitorManager {
	return &MonitorManager{
		monitors: make(map[int64]*UserMonitor),
		bot:      bot,
	}
}

// ActiveMonitorCount returns the current number of active monitors
func (mm *MonitorManager) ActiveMonitorCount() int {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	count := 0
	for _, m := range mm.monitors {
		if m.isRunning {
			count++
		}
	}
	return count
}

// StartMonitor starts monitoring for a user
func (mm *MonitorManager) StartMonitor(ctx context.Context, userID, chatID int64, creds *DecryptedCredentials) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Check if already monitoring
	if existing, exists := mm.monitors[userID]; exists && existing.isRunning {
		return fmt.Errorf("already monitoring")
	}

	// Count active monitors (check limit before creating new one)
	activeCount := 0
	for _, m := range mm.monitors {
		if m.isRunning {
			activeCount++
		}
	}

	// Enforce max concurrent monitors limit
	if activeCount >= MaxConcurrentMonitors {
		log.Printf("LIMIT | Monitor limit reached: %d/%d active monitors, rejecting user %d",
			activeCount, MaxConcurrentMonitors, userID)
		return fmt.Errorf("server at capacity (%d/%d monitors active), please try again later",
			activeCount, MaxConcurrentMonitors)
	}

	// Log warning if approaching limit
	if activeCount >= MonitorWarningThreshold {
		log.Printf("WARNING | Approaching monitor limit: %d/%d active (threshold: %d)",
			activeCount, MaxConcurrentMonitors, MonitorWarningThreshold)
	}

	// Create user-specific context
	userCtx, cancel := context.WithCancel(ctx)

	monitor := &UserMonitor{
		userID:    userID,
		chatID:    chatID,
		ctx:       userCtx,
		cancel:    cancel,
		bot:       mm.bot,
		creds:     creds,
		isRunning: false,
	}

	// Build config from user credentials
	cfg := buildConfigFromCreds(creds)

	// Initialize shared listener if not already running
	if mm.sharedListener == nil {
		sl, err := GetSharedListener(cfg)
		if err != nil {
			cancel()
			return fmt.Errorf("failed to get shared listener: %w", err)
		}
		mm.sharedListener = sl
	}

	// Start shared listener if not running
	if !mm.sharedListener.IsRunning() {
		if err := mm.sharedListener.Start(userCtx); err != nil {
			cancel()
			return fmt.Errorf("failed to start shared listener: %w", err)
		}
	}

	// Subscribe to shared listener (single websocket, broadcasted to all)
	depositsCh := mm.sharedListener.Subscribe(userID)
	monitor.depositsCh = depositsCh

	// Create analyst (receives deposits from shared listener)
	analystInstance, err := analyst.New(cfg, depositsCh)
	if err != nil {
		mm.sharedListener.Unsubscribe(userID)
		cancel()
		return fmt.Errorf("failed to create analyst: %w", err)
	}
	monitor.analyst = analystInstance

	// Start analyst
	if err := analystInstance.Start(userCtx); err != nil {
		mm.sharedListener.Unsubscribe(userID)
		cancel()
		return fmt.Errorf("failed to start analyst: %w", err)
	}

	// Create executor
	executorInstance, err := executor.New(cfg)
	if err != nil {
		analystInstance.Stop()
		mm.sharedListener.Unsubscribe(userID)
		cancel()
		return fmt.Errorf("failed to create executor: %w", err)
	}
	monitor.executor = executorInstance

	monitor.isRunning = true
	mm.monitors[userID] = monitor

	// Start goroutines to handle signals
	go monitor.handleDeposits()
	go monitor.handleTradeSignals()
	go monitor.handleErrors()

	log.Printf("Monitor started for user %d (%d/%d active monitors)",
		userID, activeCount+1, MaxConcurrentMonitors)
	return nil
}

// StopMonitor stops monitoring for a user
func (mm *MonitorManager) StopMonitor(userID int64) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	monitor, exists := mm.monitors[userID]
	if !exists {
		return
	}

	monitor.Stop()
	delete(mm.monitors, userID)

	// Unsubscribe from shared listener
	if mm.sharedListener != nil {
		mm.sharedListener.Unsubscribe(userID)
	}

	// Count remaining active monitors
	remaining := 0
	for _, m := range mm.monitors {
		if m.isRunning {
			remaining++
		}
	}
	log.Printf("Monitor stopped for user %d (%d/%d active monitors remaining)",
		userID, remaining, MaxConcurrentMonitors)
}

// IsMonitoring checks if a user is currently monitoring
func (mm *MonitorManager) IsMonitoring(userID int64) bool {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	monitor, exists := mm.monitors[userID]
	return exists && monitor.isRunning
}

// GetMonitor returns a user's monitor if running
func (mm *MonitorManager) GetMonitor(userID int64) *UserMonitor {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	return mm.monitors[userID]
}

// Stop shuts down the monitor
func (um *UserMonitor) Stop() {
	um.mu.Lock()
	defer um.mu.Unlock()

	if !um.isRunning {
		return
	}

	um.isRunning = false

	if um.analyst != nil {
		um.analyst.Stop()
	}
	// Note: we don't stop the listener here - it's shared via SharedListener
	// The MonitorManager handles unsubscribing from the shared listener
	if um.executor != nil {
		um.executor.Stop()
	}
	if um.cancel != nil {
		um.cancel()
	}
}

// handleDeposits processes deposit signals from shared listener
func (um *UserMonitor) handleDeposits() {
	for {
		select {
		case <-um.ctx.Done():
			return
		case deposit, ok := <-um.depositsCh:
			if !ok {
				return
			}
			um.notifyDeposit(deposit)
		}
	}
}

// handleTradeSignals processes trade signals from analyst
func (um *UserMonitor) handleTradeSignals() {
	for {
		select {
		case <-um.ctx.Done():
			return
		case signal, ok := <-um.analyst.TradeSignals():
			if !ok {
				return
			}
			um.notifyTradeSignal(signal)
		}
	}
}

// handleErrors processes errors from components
// Note: Listener errors are handled by SharedListener centrally
func (um *UserMonitor) handleErrors() {
	for {
		select {
		case <-um.ctx.Done():
			return
		case err, ok := <-um.analyst.Errors():
			if !ok {
				return
			}
			log.Printf("Analyst error for user %d: %v", um.userID, err)
		}
	}
}

// notifyDeposit sends a deposit notification to the user
func (um *UserMonitor) notifyDeposit(deposit *types.Deposit) {
	dollarAmount := deposit.ToDollarAmount()
	dollars, _ := dollarAmount.Float64()

	text := fmt.Sprintf(`💰 <b>High-Value Deposit Detected!</b>

<b>Amount:</b> $%.2f
<b>Address:</b> <code>%s</code>
<b>Block:</b> %d
<b>Time:</b> %s

<i>Watching for trades from this address...</i>`,
		dollars,
		escapeHTML(deposit.FunderAddress),
		deposit.BlockNumber,
		deposit.Timestamp.Format("15:04:05"),
	)

	um.bot.sendMessage(um.chatID, text)
}

// notifyTradeSignal sends a rich trade notification with action buttons
func (um *UserMonitor) notifyTradeSignal(signal *types.TradeSignal) {
	// Determine colors and emojis based on side
	sideEmoji := "🟢"
	sideText := "BUY"
	if signal.Side == types.OrderSideSell {
		sideEmoji = "🔴"
		sideText = "SELL"
	}

	outcomeEmoji := "✅"
	if signal.Outcome == "NO" {
		outcomeEmoji = "❌"
	}

	// Format the signal ID for callback data
	signalID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Store the signal for later execution
	um.storeSignal(signalID, signal)

	// Convert price to cents (e.g., 0.991 → 99.1¢)
	priceFloat := signal.GetPriceFloat()
	priceCents := priceFloat * 100

	text := fmt.Sprintf(`🎯 <b>INSIDER TRADE DETECTED!</b>

<b>Market:</b> %s

<b>Insider:</b> <code>%s</code>
<b>Insider Amount:</b> $%.2f

━━━━━━━━━━━━━━━━━━━━━━

%s <b>%s %s</b> @ <b>%.1f¢</b>

━━━━━━━━━━━━━━━━━━━━━━

<i>Tap a button to copy this trade:</i>`,
		escapeHTML(signal.Market),
		escapeHTML(signal.InsiderAddress),
		signal.InsiderAmount,
		sideEmoji,
		sideText,
		outcomeEmoji+escapeHTML(signal.Outcome),
		priceCents,
	)

	// Create action buttons
	// Amounts must be formatted as floats (e.g., "10.00") for proper parsing
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		// Row 1: Quick amounts
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🟢 $10", fmt.Sprintf("trade:exec:%s:10.00", signalID)),
			tgbotapi.NewInlineKeyboardButtonData("🟢 $25", fmt.Sprintf("trade:exec:%s:25.00", signalID)),
			tgbotapi.NewInlineKeyboardButtonData("🟢 $50", fmt.Sprintf("trade:exec:%s:50.00", signalID)),
		),
		// Row 2: Larger amounts
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🟢 $100", fmt.Sprintf("trade:exec:%s:100.00", signalID)),
			tgbotapi.NewInlineKeyboardButtonData("🟢 $250", fmt.Sprintf("trade:exec:%s:250.00", signalID)),
			tgbotapi.NewInlineKeyboardButtonData("💰 Custom", fmt.Sprintf("trade:custom:%s", signalID)),
		),
		// Row 3: Skip
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔴 Skip", fmt.Sprintf("trade:skip:%s", signalID)),
		),
	)

	um.bot.sendMessageWithKeyboard(um.chatID, text, keyboard)
}

// Signal storage for pending trades
var (
	pendingSignals   = make(map[string]*types.TradeSignal)
	pendingSignalsMu sync.RWMutex
)

// storeSignal stores a signal for later execution
func (um *UserMonitor) storeSignal(signalID string, signal *types.TradeSignal) {
	pendingSignalsMu.Lock()
	defer pendingSignalsMu.Unlock()
	pendingSignals[signalID] = signal

	// Auto-expire after 5 minutes
	go func() {
		time.Sleep(5 * time.Minute)
		pendingSignalsMu.Lock()
		delete(pendingSignals, signalID)
		pendingSignalsMu.Unlock()
	}()
}

// GetPendingSignal retrieves a pending signal
func GetPendingSignal(signalID string) *types.TradeSignal {
	pendingSignalsMu.RLock()
	defer pendingSignalsMu.RUnlock()
	return pendingSignals[signalID]
}

// RemovePendingSignal removes a pending signal
func RemovePendingSignal(signalID string) {
	pendingSignalsMu.Lock()
	defer pendingSignalsMu.Unlock()
	delete(pendingSignals, signalID)
}

// ExecuteTrade executes a trade for a user
func (um *UserMonitor) ExecuteTrade(ctx context.Context, signal *types.TradeSignal, amountUSD float64) (*TradeResult, error) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	if !um.isRunning || um.executor == nil {
		return nil, fmt.Errorf("monitor not running")
	}

	// Convert USD amount to micro-USDC (6 decimals)
	// E.g., $50 = 50,000,000 micro-USDC
	microUSDC := amountUSD * 1_000_000
	signal.Size = fmt.Sprintf("%.0f", microUSDC)

	// Execute via executor's direct method
	execResult, err := um.executor.ExecuteDirect(ctx, signal)
	if err != nil {
		return &TradeResult{
			Success:      false,
			ErrorMessage: err.Error(),
		}, err
	}

	// Convert executor result to our result type
	return &TradeResult{
		Success:      execResult.Success,
		OrderID:      execResult.OrderID,
		ErrorMessage: execResult.ErrorMessage,
		AmountUSD:    execResult.AmountUSD,
		Price:        execResult.Price,
		Shares:       execResult.Shares,
	}, nil
}

// TradeResult contains the result of a trade execution
type TradeResult struct {
	Success      bool
	OrderID      string
	ErrorMessage string
	AmountUSD    float64
	Price        float64
	Shares       float64
}

// buildConfigFromCreds creates a config from user credentials
func buildConfigFromCreds(creds *DecryptedCredentials) *config.Config {
	signatureType := 2
	if sigStr := os.Getenv("SIGNATURE_TYPE"); sigStr != "" {
		if parsed, err := strconv.Atoi(sigStr); err == nil {
			signatureType = parsed
		}
	}
	builderAPIKey := strings.TrimSpace(creds.BuilderAPIKey)
	builderSecret := strings.TrimSpace(creds.BuilderAPISecret)
	builderPassphrase := strings.TrimSpace(creds.BuilderAPIPassphrase)
	if builderAPIKey == "" {
		builderAPIKey = getEnvOrDefault("BUILDER_API_KEY", "")
	}
	if builderSecret == "" {
		builderSecret = getEnvOrDefault("BUILDER_SECRET", "")
	}
	if builderPassphrase == "" {
		builderPassphrase = getEnvOrDefault("BUILDER_PASSPHRASE", "")
	}
	return &config.Config{
		SignerPrivateKey:       creds.SignerPrivateKey,
		FunderAddress:          creds.FunderAddress,
		CLOBAPIKey:             creds.APIKey,
		CLOBAPISecret:          creds.APISecret,
		CLOBAPIPassphrase:      creds.APIPassphrase,
		BuilderAPIKey:          builderAPIKey,
		BuilderSecret:          builderSecret,
		BuilderPassphrase:      builderPassphrase,
		PolygonWSSURL:          getEnvOrDefault("POLYGON_WSS_URL", "wss://polygon-mainnet.g.alchemy.com/v2/demo"),
		CLOBAPIURL:             "https://clob.polymarket.com",
		DataAPIURL:             "https://data-api.polymarket.com",
		ChainID:                137,
		SignatureType:          signatureType,                  // POLY_GNOSIS_SAFE (browser wallet via Polymarket). Use 1 for POLY_PROXY (email/Google), 0 for EOA
		MinDepositAmount:       parseMinDeposit("10000000000"), // $10,000 in micro-USDC
		MinTradeAmount:         parseMinDeposit("1000000"),     // $1 minimum trade (1,000,000 micro-USDC)
		USDCContract:           "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		CTFContract:            "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",
		CTFExchange:            "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E",
		NegRiskCTFExchange:     "0xC5d563A36AE78145C45a50134d48A1215220f80a",
		NegRiskAdapter:         "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296",
		RelayerURL:             getEnvOrDefault("RELAYER_URL", "https://relayer-v2.polymarket.com"),
		RelayerProxyFactory:    getEnvOrDefault("RELAYER_PROXY_FACTORY", "0xaB45c5A4B0c941a2F231C04C3f49182e1A254052"),
		RelayerRelayHub:        getEnvOrDefault("RELAYER_RELAY_HUB", "0xD216153c06E857cD7f72665E0aF1d7D82172F494"),
		RelayerSafeFactory:     getEnvOrDefault("RELAYER_SAFE_FACTORY", "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b"),
		RelayerSafeMultisend:   getEnvOrDefault("RELAYER_SAFE_MULTISEND", "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"),
		RelayerSafeInitCode:    getEnvOrDefault("RELAYER_SAFE_INIT_CODE", "0x2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf"),
		RelayerProxyInitCode:   getEnvOrDefault("RELAYER_PROXY_INIT_CODE", "0xd21df8dc65880a8606f09fe0ce3df9b8869287ab0b058be05aa9e8af6330a00b"),
		RelayerSafeFactoryName: getEnvOrDefault("RELAYER_SAFE_FACTORY_NAME", "Polymarket Contract Proxy Factory"),
		RelayerProxyGasLimit:   10_000_000,
		SlippageTolerance:      3,
		MaxTradePercent:        100,
		InteractiveMode:        false, // No interactive prompts in Telegram mode
	}
}

// getEnvOrDefault gets an environment variable or returns default
func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// parseMinDeposit parses a min deposit string to big.Int
func parseMinDeposit(s string) *big.Int {
	val := new(big.Int)
	val.SetString(s, 10)
	return val
}
