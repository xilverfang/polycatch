// Package telegram provides the Telegram bot interface for Polycatch.
package telegram

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/polycatch/internal/crypto"
	"github.com/polycatch/internal/storage"
)

// BotConfig contains bot configuration options
type BotConfig struct {
	// Token is the Telegram bot token from @BotFather
	Token string

	// Debug enables verbose logging
	Debug bool

	// SessionTimeout is the session timeout in minutes
	SessionTimeout int

	// WorkerPoolSize is the number of concurrent update handlers (default: 50)
	WorkerPoolSize int

	// UpdateQueueSize is the max pending updates before backpressure (default: 500)
	UpdateQueueSize int
}

// Bot is the main Telegram bot instance
type Bot struct {
	api      *tgbotapi.BotAPI
	config   BotConfig
	db       *storage.Database
	users    *storage.UserRepository
	trades   *storage.TradeRepository
	audit    *storage.AuditRepository
	sessions *crypto.SessionManager
	monitors *MonitorManager

	// setupStates tracks users in the middle of /setup flow
	setupStates map[int64]*SetupState
	setupMu     sync.RWMutex

	// approvalStates tracks users in the middle of /approval flow
	approvalStates map[int64]*ApprovalState
	approvalMu     sync.RWMutex

	// customAmountState tracks users entering custom trade amounts
	customAmountState map[int64]string // userID -> signalID
	customAmountMu    sync.RWMutex

	// stopCh signals the bot to stop
	stopCh chan struct{}

	// Worker pool for bounded concurrency
	updateQueue chan tgbotapi.Update
	workerWg    sync.WaitGroup

	// Per-user locks for serializing updates (prevents race conditions)
	userLocks   map[int64]*sync.Mutex
	userLocksMu sync.Mutex

	// tradesDashboard tracks per-user /trades dashboard state (e.g., order IDs for short callbacks).
	tradesDashboard   map[int64]*TradesDashboardState
	tradesDashboardMu sync.RWMutex
}

// TradesDashboardState stores ephemeral state needed to handle /trades callbacks without
// exceeding Telegram's 64-byte callback_data limit.
type TradesDashboardState struct {
	OrderIDs  []string
	UpdatedAt time.Time
}

// SetupState tracks the state of a user's /setup flow
type SetupState struct {
	Step          SetupStep
	Password      *crypto.SecureBuffer
	PrivateKey    *crypto.SecureBuffer
	FunderAddress string
	APIKey        *crypto.SecureBuffer
	APISecret     *crypto.SecureBuffer
	APIPassphrase *crypto.SecureBuffer
	StartedAt     time.Time
	LastMessageID int
}

// SetupStep represents the current step in the setup flow
type SetupStep int

const (
	SetupStepPassword SetupStep = iota + 1
	SetupStepConfirmPassword
	SetupStepPrivateKey
	SetupStepFunderAddress
)

// NewBot creates a new Telegram bot instance
func NewBot(config BotConfig, db *storage.Database) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(config.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create bot API: %w", err)
	}

	api.Debug = config.Debug

	sessionTimeout := time.Duration(config.SessionTimeout) * time.Minute
	if sessionTimeout == 0 {
		sessionTimeout = 30 * time.Minute
	}

	// Apply worker pool defaults
	workerPoolSize := config.WorkerPoolSize
	if workerPoolSize <= 0 {
		workerPoolSize = 50 // Default: 50 concurrent handlers
	}
	updateQueueSize := config.UpdateQueueSize
	if updateQueueSize <= 0 {
		updateQueueSize = 500 // Default: buffer 500 updates before backpressure
	}

	bot := &Bot{
		api:               api,
		config:            config,
		db:                db,
		users:             storage.NewUserRepository(db),
		trades:            storage.NewTradeRepository(db),
		audit:             storage.NewAuditRepository(db),
		sessions:          crypto.NewSessionManager(sessionTimeout),
		setupStates:       make(map[int64]*SetupState),
		approvalStates:    make(map[int64]*ApprovalState),
		customAmountState: make(map[int64]string),
		stopCh:            make(chan struct{}),
		updateQueue:       make(chan tgbotapi.Update, updateQueueSize),
		userLocks:         make(map[int64]*sync.Mutex),
		tradesDashboard:   make(map[int64]*TradesDashboardState),
	}

	// Initialize monitor manager (needs bot reference, so set after creation)
	bot.monitors = NewMonitorManager(bot)

	// Register bot commands so users can tap them (Telegram command list UI)
	bot.registerBotCommands()

	log.Printf("Bot authenticated as @%s (workers=%d, queue=%d)", api.Self.UserName, workerPoolSize, updateQueueSize)
	return bot, nil
}

func (b *Bot) registerBotCommands() {
	commands := []tgbotapi.BotCommand{
		{Command: "start", Description: "Welcome + quick setup info"},
		{Command: "help", Description: "Show all commands"},
		{Command: "setup", Description: "Create your account"},
		{Command: "approval", Description: "Add Builder keys for approvals"},
		{Command: "unlock", Description: "Start a session"},
		{Command: "lock", Description: "End your session"},
		{Command: "status", Description: "View account status"},
		{Command: "settings", Description: "View and modify settings"},
		{Command: "monitor", Description: "Start monitoring for insider signals"},
		{Command: "crypto", Description: "Trade crypto 15-min markets"},
		{Command: "stop", Description: "Stop monitoring"},
		{Command: "trades", Description: "View trade history"},
		{Command: "cancel", Description: "Cancel current operation"},
		{Command: "delete", Description: "Delete your account"},
	}

	_, err := b.api.Request(tgbotapi.NewSetMyCommands(commands...))
	if err != nil {
		log.Printf("WARNING | Failed to set bot commands: %v", err)
	}
}

// Start starts the bot and blocks until context is cancelled
func (b *Bot) Start(ctx context.Context) error {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := b.api.GetUpdatesChan(u)

	// Start cleanup goroutine for expired setup states
	go b.cleanupSetupStates(ctx)
	// Start cleanup goroutine for expired approval states
	go b.cleanupApprovalStates(ctx)

	// Start worker pool
	workerCount := b.config.WorkerPoolSize
	if workerCount <= 0 {
		workerCount = 50
	}
	for i := 0; i < workerCount; i++ {
		b.workerWg.Add(1)
		go b.updateWorker(ctx)
	}

	// Dispatch updates to worker pool
	for {
		select {
		case <-ctx.Done():
			b.api.StopReceivingUpdates()
			close(b.updateQueue)
			b.workerWg.Wait()
			return ctx.Err()

		case <-b.stopCh:
			b.api.StopReceivingUpdates()
			close(b.updateQueue)
			b.workerWg.Wait()
			return nil

		case update := <-updates:
			// Non-blocking send with backpressure handling
			select {
			case b.updateQueue <- update:
				// Queued successfully
			default:
				// Queue full - apply backpressure by blocking briefly then dropping if still full
				select {
				case b.updateQueue <- update:
					// Queued after brief wait
				case <-time.After(100 * time.Millisecond):
					log.Printf("WARN | Update queue full, dropping update from user %d", getUserIDFromUpdate(update))
				}
			}
		}
	}
}

// updateWorker processes updates from the queue
func (b *Bot) updateWorker(ctx context.Context) {
	defer b.workerWg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-b.updateQueue:
			if !ok {
				return // Queue closed
			}
			b.handleUpdate(ctx, update)
		}
	}
}

// getUserIDFromUpdate extracts user ID from an update for logging
func getUserIDFromUpdate(update tgbotapi.Update) int64 {
	if update.Message != nil && update.Message.From != nil {
		return update.Message.From.ID
	}
	if update.CallbackQuery != nil && update.CallbackQuery.From != nil {
		return update.CallbackQuery.From.ID
	}
	return 0
}

// Stop stops the bot
func (b *Bot) Stop() {
	close(b.stopCh)
}

// getUserLock returns a per-user mutex for serializing that user's updates
func (b *Bot) getUserLock(userID int64) *sync.Mutex {
	b.userLocksMu.Lock()
	defer b.userLocksMu.Unlock()

	lock, exists := b.userLocks[userID]
	if !exists {
		lock = &sync.Mutex{}
		b.userLocks[userID] = lock
	}
	return lock
}

// handleUpdate routes incoming updates to appropriate handlers
func (b *Bot) handleUpdate(ctx context.Context, update tgbotapi.Update) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic in update handler: %v", r)
		}
	}()

	// Acquire per-user lock to serialize updates for the same user
	// This prevents race conditions in setup flows, trade confirmations, etc.
	userID := getUserIDFromUpdate(update)
	if userID != 0 {
		userLock := b.getUserLock(userID)
		userLock.Lock()
		defer userLock.Unlock()
	}

	// Handle callback queries (inline button presses)
	if update.CallbackQuery != nil {
		b.handleCallback(ctx, update.CallbackQuery)
		return
	}

	// Handle messages
	if update.Message == nil {
		return
	}

	msg := update.Message
	chatID := msg.Chat.ID

	// Check if user is in setup flow
	if b.isInSetup(userID) {
		b.handleSetupInput(ctx, msg)
		return
	}

	// Check if user is in approval flow
	if b.isInApproval(userID) {
		b.handleApprovalInput(ctx, msg)
		return
	}

	// Handle commands
	if msg.IsCommand() {
		b.handleCommand(ctx, msg)
		return
	}

	// Handle text messages (for unlock password, etc.)
	b.handleTextMessage(ctx, msg, userID, chatID)
}

// handleCommand routes commands to their handlers
func (b *Bot) handleCommand(ctx context.Context, msg *tgbotapi.Message) {
	userID := msg.From.ID
	chatID := msg.Chat.ID
	command := msg.Command()

	log.Printf("Command /%s from user %d", command, userID)

	switch command {
	case "start":
		b.cmdStart(ctx, chatID, userID, msg.From.UserName)

	case "help":
		b.cmdHelp(ctx, chatID)

	case "setup":
		b.cmdSetup(ctx, chatID, userID)

	case "approval":
		b.cmdApproval(ctx, chatID, userID)

	case "unlock":
		b.cmdUnlock(ctx, chatID, userID, msg.CommandArguments())

	case "lock":
		b.cmdLock(ctx, chatID, userID)

	case "status":
		b.cmdStatus(ctx, chatID, userID)

	case "settings":
		b.cmdSettings(ctx, chatID, userID)

	case "trades":
		b.cmdTrades(ctx, chatID, userID)

	case "trade":
		b.cmdPositions(ctx, chatID, userID)

	case "monitor":
		b.cmdMonitor(ctx, chatID, userID)

	case "stop":
		b.cmdStopMonitor(ctx, chatID, userID)

	case "delete":
		b.cmdDelete(ctx, chatID, userID)

	case "cancel":
		b.cmdCancel(ctx, chatID, userID)

	case "crypto":
		b.cmdCrypto(ctx, chatID, userID)

	case "positions":
		b.cmdPositions(ctx, chatID, userID)

	default:
		b.sendMessage(chatID, "❓ Unknown command. Use /help to see available commands.")
	}
}

// handleTextMessage handles non-command text messages
func (b *Bot) handleTextMessage(ctx context.Context, msg *tgbotapi.Message, userID int64, chatID int64) {
	// Check for password input (for /unlock without inline argument)
	// This is handled securely - we delete the message containing the password
	text := strings.TrimSpace(msg.Text)

	if text == "" {
		return
	}

	// Check for custom amount input (user entering trade amount)
	if b.handleCustomAmountInput(ctx, chatID, userID, text) {
		// Delete the amount message for cleaner UI
		b.deleteMessage(chatID, msg.MessageID)
		return
	}

	// Check for crypto limit price input
	if b.handleCryptoLimitPriceInput(ctx, chatID, userID, text) {
		b.deleteMessage(chatID, msg.MessageID)
		return
	}

	// Check for limit sell price input
	if b.handleLimitSellPriceInput(ctx, chatID, userID, text) {
		b.deleteMessage(chatID, msg.MessageID)
		return
	}

	// Check for crypto custom amount input
	if b.handleCryptoCustomAmount(ctx, chatID, userID, text) {
		b.deleteMessage(chatID, msg.MessageID)
		return
	}

	// If there's an active unlock prompt, try to use this as the password
	session := b.sessions.GetSession(userID)
	if session == nil {
		// Check if user exists and might be trying to unlock
		exists, _ := b.users.Exists(ctx, userID)
		if exists && len(text) >= 12 {
			// Might be a password attempt - try to unlock
			b.tryUnlock(ctx, chatID, userID, text, msg.MessageID)
			return
		}
	}

	// Generic response for unexpected messages
	b.sendMessage(chatID, "💡 Use /help to see available commands.")
}

// handleCallback handles inline button callbacks
func (b *Bot) handleCallback(ctx context.Context, callback *tgbotapi.CallbackQuery) {
	userID := callback.From.ID
	chatID := callback.Message.Chat.ID
	data := callback.Data

	// Acknowledge the callback
	b.api.Request(tgbotapi.NewCallback(callback.ID, ""))

	log.Printf("Callback %s from user %d", data, userID)

	parts := strings.Split(data, ":")
	if len(parts) == 0 {
		return
	}

	action := parts[0]

	switch action {
	case "setup_confirm":
		b.handleSetupConfirm(ctx, chatID, userID, true)

	case "setup_cancel":
		b.handleSetupConfirm(ctx, chatID, userID, false)

	case "approval_confirm":
		b.handleApprovalConfirm(ctx, chatID, userID, true)

	case "approval_cancel":
		b.handleApprovalConfirm(ctx, chatID, userID, false)

	case "delete_confirm":
		b.handleDeleteConfirm(ctx, chatID, userID, callback.Message.MessageID)

	case "delete_cancel":
		b.editMessage(chatID, callback.Message.MessageID, "❌ Account deletion cancelled.")

	case "trade":
		if len(parts) >= 3 {
			// Rejoin parts[2:] to preserve signalID:amount format
			// Callback format: trade:action:signalID:amount
			remainingData := strings.Join(parts[2:], ":")
			b.handleTradeCallback(ctx, chatID, userID, parts[1], remainingData)
		}

	case "settings":
		if len(parts) >= 2 {
			b.handleSettingsCallback(ctx, chatID, userID, parts[1], callback.Message.MessageID)
		}

	case "crypto":
		if len(parts) >= 2 {
			// Handle crypto callbacks - format: crypto:action or crypto:action_param
			action := parts[1]
			// Check for confirm action with amount
			if strings.HasPrefix(action, "confirm_") {
				amountStr := strings.TrimPrefix(action, "confirm_")
				b.handleCryptoConfirmWithAmount(ctx, chatID, userID, amountStr, callback.Message.MessageID)
			} else if action == "back_main" {
				b.cmdCrypto(ctx, chatID, userID)
			} else {
				b.handleCryptoCallback(ctx, chatID, userID, action, callback.Message.MessageID)
			}
		}

	case "sell":
		if len(parts) >= 2 {
			// Handle sell callbacks - format: sell:action or sell:action_param
			action := parts[1]
			b.handleSellCallback(ctx, chatID, userID, action, callback.Message.MessageID)
		}

	case "trades":
		if len(parts) >= 2 {
			b.handleTradesCallback(ctx, chatID, userID, parts[1], callback.Message.MessageID)
		}
	}
}

// isInSetup checks if a user is in the setup flow
func (b *Bot) isInSetup(userID int64) bool {
	b.setupMu.RLock()
	defer b.setupMu.RUnlock()
	_, exists := b.setupStates[userID]
	return exists
}

// isInApproval checks if a user is in the approval flow
func (b *Bot) isInApproval(userID int64) bool {
	b.approvalMu.RLock()
	defer b.approvalMu.RUnlock()
	_, exists := b.approvalStates[userID]
	return exists
}

// getSetupState gets a user's setup state
func (b *Bot) getSetupState(userID int64) *SetupState {
	b.setupMu.RLock()
	defer b.setupMu.RUnlock()
	return b.setupStates[userID]
}

func (b *Bot) getApprovalState(userID int64) *ApprovalState {
	b.approvalMu.RLock()
	defer b.approvalMu.RUnlock()
	return b.approvalStates[userID]
}

// setSetupState sets a user's setup state
func (b *Bot) setSetupState(userID int64, state *SetupState) {
	b.setupMu.Lock()
	defer b.setupMu.Unlock()
	b.setupStates[userID] = state
}

func (b *Bot) setApprovalState(userID int64, state *ApprovalState) {
	b.approvalMu.Lock()
	defer b.approvalMu.Unlock()
	b.approvalStates[userID] = state
}

// clearSetupState clears a user's setup state and sensitive data
func (b *Bot) clearSetupState(userID int64) {
	b.setupMu.Lock()
	defer b.setupMu.Unlock()

	if state, exists := b.setupStates[userID]; exists {
		// Securely clear sensitive data
		state.ClearSensitive()
		delete(b.setupStates, userID)
	}
}

// clearApprovalState clears a user's approval state and sensitive data
func (b *Bot) clearApprovalState(userID int64) {
	b.approvalMu.Lock()
	defer b.approvalMu.Unlock()

	if state, exists := b.approvalStates[userID]; exists {
		state.ClearSensitive()
		delete(b.approvalStates, userID)
	}
}

// cleanupSetupStates periodically cleans up expired setup states
func (b *Bot) cleanupSetupStates(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.setupMu.Lock()
			now := time.Now()
			for userID, state := range b.setupStates {
				// Expire setup states older than 10 minutes
				if now.Sub(state.StartedAt) > 10*time.Minute {
					state.ClearSensitive()
					delete(b.setupStates, userID)
					log.Printf("Expired setup state for user %d", userID)
				}
			}
			b.setupMu.Unlock()
		}
	}
}

// cleanupApprovalStates periodically cleans up expired approval states
func (b *Bot) cleanupApprovalStates(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.approvalMu.Lock()
			now := time.Now()
			for userID, state := range b.approvalStates {
				if now.Sub(state.StartedAt) > 10*time.Minute {
					state.ClearSensitive()
					delete(b.approvalStates, userID)
					log.Printf("Expired approval state for user %d", userID)
				}
			}
			b.approvalMu.Unlock()
		}
	}
}

// sendMessage sends a text message
func (b *Bot) sendMessage(chatID int64, text string) int {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "HTML"
	msg.DisableWebPagePreview = true

	sent, err := b.api.Send(msg)
	if err != nil {
		log.Printf("Failed to send message: %v", err)
		return 0
	}
	return sent.MessageID
}

// sendMessageWithKeyboard sends a message with inline keyboard
func (b *Bot) sendMessageWithKeyboard(chatID int64, text string, keyboard tgbotapi.InlineKeyboardMarkup) int {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "HTML"
	msg.DisableWebPagePreview = true
	msg.ReplyMarkup = keyboard

	sent, err := b.api.Send(msg)
	if err != nil {
		log.Printf("Failed to send message with keyboard: %v", err)
		return 0
	}
	return sent.MessageID
}

// editMessage edits an existing message
func (b *Bot) editMessage(chatID int64, messageID int, text string) {
	edit := tgbotapi.NewEditMessageText(chatID, messageID, text)
	edit.ParseMode = "HTML"
	edit.DisableWebPagePreview = true

	if _, err := b.api.Send(edit); err != nil {
		log.Printf("Failed to edit message: %v", err)
	}
}

// deleteMessage deletes a message (for removing sensitive data)
func (b *Bot) deleteMessage(chatID int64, messageID int) {
	del := tgbotapi.NewDeleteMessage(chatID, messageID)
	if _, err := b.api.Request(del); err != nil {
		log.Printf("Failed to delete message: %v", err)
	}
}

// sendAndDelete sends a message that auto-deletes after a delay
func (b *Bot) sendAndDelete(chatID int64, text string, delay time.Duration) {
	msgID := b.sendMessage(chatID, text)
	if msgID > 0 {
		go func() {
			time.Sleep(delay)
			b.deleteMessage(chatID, msgID)
		}()
	}
}
