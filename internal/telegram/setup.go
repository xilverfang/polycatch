package telegram

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/polycatch/internal/apikey"
	"github.com/polycatch/internal/config"
	"github.com/polycatch/internal/crypto"
	"github.com/polycatch/internal/storage"
)

// cmdSetup handles the /setup command - starts the account creation flow
func (b *Bot) cmdSetup(ctx context.Context, chatID int64, userID int64) {
	// Check if user already exists
	exists, _ := b.users.Exists(ctx, userID)
	if exists {
		b.sendMessage(chatID, `⚠️ You already have an account.

Use /unlock to access your account.
Use /delete if you want to start fresh.`)
		return
	}

	// Clear any existing setup state
	b.clearSetupState(userID)

	// Start setup flow
	state := &SetupState{
		Step:      SetupStepPassword,
		StartedAt: time.Now(),
	}
	b.setSetupState(userID, state)

	text := `🔐 <b>Account Setup</b>

Let's set up your Polywatch account securely. This takes about 2 minutes.

<b>Step 1/4: Encryption Password</b>

Create a strong password to encrypt your credentials. This password:
• Encrypts all your sensitive data
• Is NEVER stored anywhere
• Cannot be recovered if lost

<b>Requirements:</b>
• At least 12 characters
• Mix of uppercase, lowercase, numbers, symbols

⚠️ <b>Important:</b> Your messages will be auto-deleted for security.

Please enter your encryption password:`

	msgID := b.sendMessage(chatID, text)

	// Auto-delete the instruction message
	go func() {
		time.Sleep(60 * time.Second)
		b.deleteMessage(chatID, msgID)
	}()
}

// handleSetupInput handles user input during the setup flow
func (b *Bot) handleSetupInput(ctx context.Context, msg *tgbotapi.Message) {
	userID := msg.From.ID
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)
	messageID := msg.MessageID

	state := b.getSetupState(userID)
	if state == nil {
		return
	}

	// Always delete user's input message (contains sensitive data)
	b.deleteMessage(chatID, messageID)

	// Delete the last bot message if we're tracking it
	if state.LastMessageID > 0 {
		b.deleteMessage(chatID, state.LastMessageID)
	}

	switch state.Step {
	case SetupStepPassword:
		b.handleSetupPassword(ctx, chatID, userID, text, state)

	case SetupStepConfirmPassword:
		b.handleSetupConfirmPassword(ctx, chatID, userID, text, state)

	case SetupStepPrivateKey:
		b.handleSetupPrivateKey(ctx, chatID, userID, text, state)

	case SetupStepFunderAddress:
		b.handleSetupFunderAddress(ctx, chatID, userID, text, state)
	}
}

func (b *Bot) handleSetupPassword(ctx context.Context, chatID int64, userID int64, password string, state *SetupState) {
	// Check password strength
	strength, suggestions := crypto.CheckPasswordStrength(password)

	if strength == crypto.PasswordWeak {
		text := "❌ <b>Password too weak</b>\n\n"
		for _, s := range suggestions {
			text += fmt.Sprintf("• %s\n", s)
		}
		text += "\nPlease enter a stronger password:"

		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	// Store password temporarily (will be cleared after setup)
	state.SetPassword(password)
	state.Step = SetupStepConfirmPassword

	strengthText := "Fair"
	if strength == crypto.PasswordStrong {
		strengthText = "Strong"
	} else if strength == crypto.PasswordExcellent {
		strengthText = "Excellent"
	}

	text := fmt.Sprintf(`✅ Password strength: <b>%s</b>

<b>Step 2/4: Confirm Password</b>

Please enter your password again to confirm:`, strengthText)

	state.LastMessageID = b.sendMessage(chatID, text)
	b.setSetupState(userID, state)
}

func (b *Bot) handleSetupConfirmPassword(ctx context.Context, chatID int64, userID int64, confirm string, state *SetupState) {
	if !state.PasswordMatches(confirm) {
		text := `❌ <b>Passwords don't match</b>

Please enter your password again to confirm:`

		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.Step = SetupStepPrivateKey

	text := `✅ Password confirmed!

<b>Step 3/4: Signer Private Key</b>

Enter your MetaMask/wallet private key. This is used to sign orders.

Format: <code>0x</code> followed by 64 hex characters

⚠️ <b>Security Tips:</b>
• Use a dedicated trading wallet, NOT your main wallet
• This key will be encrypted with your password
• Never share this key with anyone

Enter your private key:`

	state.LastMessageID = b.sendMessage(chatID, text)
	b.setSetupState(userID, state)
}

func (b *Bot) handleSetupPrivateKey(ctx context.Context, chatID int64, userID int64, key string, state *SetupState) {
	// Validate private key format
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "0x") {
		key = "0x" + key
	}

	// Check format: 0x + 64 hex characters
	matched, _ := regexp.MatchString(`^0x[0-9a-fA-F]{64}$`, key)
	if !matched {
		text := `❌ <b>Invalid private key format</b>

Expected format: <code>0x</code> + 64 hex characters

Please enter a valid private key:`

		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.SetPrivateKey(key)
	state.Step = SetupStepFunderAddress

	text := `✅ Private key validated!

<b>Step 4/4: Funder Address</b>

Enter your Polymarket proxy wallet address (the one that holds your funds on Polymarket).

Format: <code>0x</code> followed by 40 hex characters

💡 <b>Tip:</b> This is your Polymarket profile address, NOT your MetaMask address.
You can find it in your Polymarket profile settings.

Enter your funder address:`

	state.LastMessageID = b.sendMessage(chatID, text)
	b.setSetupState(userID, state)
}

func (b *Bot) handleSetupFunderAddress(ctx context.Context, chatID int64, userID int64, address string, state *SetupState) {
	address = strings.TrimSpace(address)
	if !strings.HasPrefix(address, "0x") {
		address = "0x" + address
	}

	// Validate address format
	matched, _ := regexp.MatchString(`^0x[0-9a-fA-F]{40}$`, address)
	if !matched {
		text := `❌ <b>Invalid address format</b>

Expected format: <code>0x</code> + 40 hex characters

Please enter a valid address:`

		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.FunderAddress = address

	// Show "generating" message
	genMsgID := b.sendMessage(chatID, `⏳ <b>Generating API Credentials...</b>

This may take a few seconds. Please wait...`)

	// Generate API credentials automatically
	apiCreds, err := b.generateAPICredentials(ctx, state.PrivateKeyString())

	// Delete the generating message
	b.deleteMessage(chatID, genMsgID)

	if err != nil {
		log.Printf("Failed to generate API credentials for user %d: %v", userID, err)

		text := fmt.Sprintf(`❌ <b>Failed to generate API credentials</b>

Error: %s

Please try again with /setup or contact support.`, escapeHTML(err.Error()))

		b.sendMessage(chatID, text)
		b.clearSetupState(userID)
		return
	}

	// Store API credentials in state
	state.SetAPIKey(apiCreds.APIKey)
	state.SetAPISecret(apiCreds.Secret)
	state.SetAPIPassphrase(apiCreds.Passphrase)

	// Show confirmation
	maskedKey := maskString(state.PrivateKeyString(), 6, 4)

	text := fmt.Sprintf(`✅ <b>API Credentials Generated!</b>

<b>Review Your Setup:</b>
🔑 Private Key: <code>%s</code>
📍 Funder Address: <code>%s</code>
🔐 API Key: <code>%s</code>
✅ API Secret: Generated
✅ API Passphrase: Generated

Your data will be encrypted with AES-256-GCM and can only be decrypted with your password.

<b>Ready to save?</b>`,
		maskedKey,
		state.FunderAddress,
		maskString(state.APIKeyString(), 8, 4),
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Confirm & Save", "setup_confirm"),
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "setup_cancel"),
		),
	)

	b.sendMessageWithKeyboard(chatID, text, keyboard)
	b.setSetupState(userID, state)
}

// generateAPICredentials creates API credentials using the signer private key
func (b *Bot) generateAPICredentials(ctx context.Context, privateKey string) (*apikey.APIKeyResponse, error) {
	// Create a temporary config with just the private key
	cfg := &config.Config{
		SignerPrivateKey: privateKey,
		CLOBAPIURL:       "https://clob.polymarket.com",
		ChainID:          137, // Polygon mainnet
	}

	// Generate API credentials
	return apikey.CreateAPIKey(ctx, cfg)
}

// handleSetupConfirm handles the final setup confirmation
func (b *Bot) handleSetupConfirm(ctx context.Context, chatID int64, userID int64, confirmed bool) {
	state := b.getSetupState(userID)
	if state == nil {
		b.sendMessage(chatID, "❌ Setup session expired. Please use /setup to start again.")
		return
	}

	if !confirmed {
		b.clearSetupState(userID)
		b.sendMessage(chatID, "❌ Setup cancelled. Your data has been cleared.\n\nUse /setup to start again.")
		return
	}

	// Create credentials
	creds := &storage.UserCredentials{
		SignerPrivateKey: state.PrivateKeyString(),
		FunderAddress:    state.FunderAddress,
		APIKey:           state.APIKeyString(),
		APISecret:        state.APISecretString(),
		APIPassphrase:    state.APIPassphraseString(),
	}

	// Get username (empty for now, could be fetched from Telegram)
	username := ""

	// Create user in database
	err := b.users.Create(ctx, userID, username, state.PasswordString(), creds)

	// Clear sensitive data immediately
	b.clearSetupState(userID)

	if err != nil {
		log.Printf("Failed to create user %d: %v", userID, err)
		b.sendMessage(chatID, "❌ Failed to create account. Please try again with /setup")
		return
	}

	// Log registration
	b.audit.LogRegister(ctx, userID, username)

	text := `🎉 <b>Account Created Successfully!</b>

Your credentials have been securely encrypted and saved.

<b>Next steps:</b>
1️⃣ Use /unlock to start a session
2️⃣ Use /monitor to start watching for insider trades
3️⃣ Use /settings to customize your preferences

<b>Remember:</b>
• Your password is NOT stored anywhere
• If you forget it, you'll need to /delete and /setup again
• Sessions auto-lock after 30 minutes

Welcome to Polywatch! 🔮`

	b.sendMessage(chatID, text)
}

// maskString masks a string showing only first and last n characters
func maskString(s string, showFirst, showLast int) string {
	if len(s) <= showFirst+showLast {
		return strings.Repeat("*", len(s))
	}
	return s[:showFirst] + strings.Repeat("*", len(s)-showFirst-showLast) + s[len(s)-showLast:]
}
