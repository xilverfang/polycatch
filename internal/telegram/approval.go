package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/polycatch/internal/crypto"
	"github.com/polycatch/internal/executor"
	"github.com/polycatch/internal/storage"
)

// ApprovalState tracks the state of a user's /approval flow
type ApprovalState struct {
	Step                 ApprovalStep
	Password             *crypto.SecureBuffer
	BuilderAPIKey        *crypto.SecureBuffer
	BuilderAPISecret     *crypto.SecureBuffer
	BuilderAPIPassphrase *crypto.SecureBuffer
	StartedAt            time.Time
	LastMessageID        int
}

// ApprovalStep represents the current step in the approval flow
type ApprovalStep int

const (
	ApprovalStepPassword ApprovalStep = iota + 1
	ApprovalStepBuilderKey
	ApprovalStepBuilderSecret
	ApprovalStepBuilderPassphrase
)

// cmdApproval handles the /approval command - sets Builder credentials for relayer approvals
func (b *Bot) cmdApproval(ctx context.Context, chatID int64, userID int64) {
	// Check if user already exists
	exists, _ := b.users.Exists(ctx, userID)
	if !exists {
		b.sendMessage(chatID, "❌ You don't have an account yet. Use /setup to create one.")
		return
	}
	// Require an unlocked session (consistent with other sensitive flows)
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Please /unlock your session before running /approval.")
		return
	}

	creds, credErr := b.GetSessionCredentials(userID)
	if credErr == nil && creds != nil &&
		strings.TrimSpace(creds.BuilderAPIKey) != "" &&
		strings.TrimSpace(creds.BuilderAPISecret) != "" &&
		strings.TrimSpace(creds.BuilderAPIPassphrase) != "" {
		b.sendMessage(chatID, "✅ Builder credentials already set. Running approvals now…")
		if err := b.runApprovalTransactions(ctx, creds); err != nil {
			b.sendMessage(chatID, fmt.Sprintf("❌ Approvals failed: %s", escapeHTML(err.Error())))
		} else {
			b.sendMessage(chatID, "✅ Approvals completed. You can now trade.")
		}
		return
	}

	// Clear any existing approval state
	b.clearApprovalState(userID)

	state := &ApprovalState{
		Step:      ApprovalStepPassword,
		StartedAt: time.Now(),
	}
	b.setApprovalState(userID, state)

	text := `✅ <b>Relayer Approval Setup</b>

We'll save your Builder API keys so approvals can be sent to the relayer.

<b>Step 1/4: Encryption Password</b>

Enter your encryption password to update your credentials.

⚠️ <b>Your message will be deleted for security.</b>`

	msgID := b.sendMessage(chatID, text)
	state.LastMessageID = msgID
	b.setApprovalState(userID, state)
}

// handleApprovalInput handles user input during the approval flow
func (b *Bot) handleApprovalInput(ctx context.Context, msg *tgbotapi.Message) {
	userID := msg.From.ID
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)
	messageID := msg.MessageID

	state := b.getApprovalState(userID)
	if state == nil {
		return
	}
	// Require an active session while in approval flow
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.clearApprovalState(userID)
		b.sendMessage(chatID, "🔒 Your session is locked. Use /unlock, then /approval again.")
		return
	}

	// Always delete user's input message (contains sensitive data)
	b.deleteMessage(chatID, messageID)

	// Delete the last bot message if we're tracking it
	if state.LastMessageID > 0 {
		b.deleteMessage(chatID, state.LastMessageID)
	}

	switch state.Step {
	case ApprovalStepPassword:
		b.handleApprovalPassword(ctx, chatID, userID, text, state)
	case ApprovalStepBuilderKey:
		b.handleApprovalBuilderKey(chatID, userID, text, state)
	case ApprovalStepBuilderSecret:
		b.handleApprovalBuilderSecret(chatID, userID, text, state)
	case ApprovalStepBuilderPassphrase:
		b.handleApprovalBuilderPassphrase(chatID, userID, text, state)
	}
}

func (b *Bot) handleApprovalPassword(ctx context.Context, chatID int64, userID int64, password string, state *ApprovalState) {
	// Ensure session is still valid
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.clearApprovalState(userID)
		b.sendMessage(chatID, "🔒 Your session is locked. Use /unlock, then /approval again.")
		return
	}
	// Verify password by attempting to decrypt credentials
	_, err := b.users.DecryptCredentials(ctx, userID, password)
	if err != nil {
		text := `❌ <b>Invalid password</b>

Please enter your encryption password again:`
		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.SetPassword(password)
	state.Step = ApprovalStepBuilderKey

	text := `✅ Password verified!

<b>Step 2/4: Builder API Key</b>

Enter your Builder API key from Polymarket Builder settings:`

	state.LastMessageID = b.sendMessage(chatID, text)
	b.setApprovalState(userID, state)
}

func (b *Bot) handleApprovalBuilderKey(chatID int64, userID int64, apiKey string, state *ApprovalState) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		text := "❌ <b>Builder API key cannot be empty</b>\n\nPlease enter your Builder API key:"
		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.SetBuilderAPIKey(apiKey)
	state.Step = ApprovalStepBuilderSecret

	text := `✅ Builder API key saved!

<b>Step 3/4: Builder API Secret</b>

Enter your Builder API secret:`

	state.LastMessageID = b.sendMessage(chatID, text)
	b.setApprovalState(userID, state)
}

func (b *Bot) handleApprovalBuilderSecret(chatID int64, userID int64, secret string, state *ApprovalState) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		text := "❌ <b>Builder API secret cannot be empty</b>\n\nPlease enter your Builder API secret:"
		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.SetBuilderAPISecret(secret)
	state.Step = ApprovalStepBuilderPassphrase

	text := `✅ Builder API secret saved!

<b>Step 4/4: Builder API Passphrase</b>

Enter your Builder API passphrase:`

	state.LastMessageID = b.sendMessage(chatID, text)
	b.setApprovalState(userID, state)
}

func (b *Bot) handleApprovalBuilderPassphrase(chatID int64, userID int64, passphrase string, state *ApprovalState) {
	passphrase = strings.TrimSpace(passphrase)
	if passphrase == "" {
		text := "❌ <b>Builder API passphrase cannot be empty</b>\n\nPlease enter your Builder API passphrase:"
		state.LastMessageID = b.sendMessage(chatID, text)
		return
	}

	state.SetBuilderAPIPassphrase(passphrase)

	maskedKey := maskString(state.BuilderAPIKeyString(), 8, 4)
	text := fmt.Sprintf(`✅ <b>Builder Credentials Ready</b>

<b>Review:</b>
🔑 Builder API Key: <code>%s</code>
🔐 Builder Secret: ✅ Set
✅ Builder Passphrase: ✅ Set

Save these credentials?`, maskedKey)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Confirm & Save", "approval_confirm"),
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "approval_cancel"),
		),
	)

	state.LastMessageID = b.sendMessageWithKeyboard(chatID, text, keyboard)
	b.setApprovalState(userID, state)
}

func (b *Bot) handleApprovalConfirm(ctx context.Context, chatID int64, userID int64, confirmed bool) {
	state := b.getApprovalState(userID)
	if state == nil {
		b.sendMessage(chatID, "❌ Approval session expired. Use /approval to start again.")
		return
	}

	if !confirmed {
		b.clearApprovalState(userID)
		b.sendMessage(chatID, "❌ Approval setup cancelled. Your data was not saved.")
		return
	}

	password := state.PasswordString()
	creds, err := b.users.DecryptCredentials(ctx, userID, password)
	if err != nil {
		b.sendMessage(chatID, "❌ Failed to decrypt credentials. Please try /approval again.")
		b.clearApprovalState(userID)
		return
	}

	creds.BuilderAPIKey = state.BuilderAPIKeyString()
	creds.BuilderAPISecret = state.BuilderAPISecretString()
	creds.BuilderAPIPassphrase = state.BuilderAPIPassphraseString()

	if err := b.users.UpdateCredentials(ctx, userID, password, creds); err != nil {
		b.sendMessage(chatID, fmt.Sprintf("❌ Failed to save credentials: %s", escapeHTML(err.Error())))
		b.clearApprovalState(userID)
		return
	}

	b.updateSessionCredentials(userID, creds)
	b.clearApprovalState(userID)

	b.sendMessage(chatID, "✅ Builder credentials saved. Running approvals now…")
	if err := b.runApprovalTransactions(ctx, &DecryptedCredentials{
		SignerPrivateKey:     creds.SignerPrivateKey,
		FunderAddress:        creds.FunderAddress,
		APIKey:               creds.APIKey,
		APISecret:            creds.APISecret,
		APIPassphrase:        creds.APIPassphrase,
		BuilderAPIKey:        creds.BuilderAPIKey,
		BuilderAPISecret:     creds.BuilderAPISecret,
		BuilderAPIPassphrase: creds.BuilderAPIPassphrase,
	}); err != nil {
		b.sendMessage(chatID, fmt.Sprintf("❌ Approvals failed: %s", escapeHTML(err.Error())))
		return
	}
	b.sendMessage(chatID, "✅ Approvals completed. You can now trade.")
}

func (b *Bot) updateSessionCredentials(userID int64, creds *storage.UserCredentials) {
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		return
	}

	credsData, _ := json.Marshal(DecryptedCredentials{
		SignerPrivateKey:     creds.SignerPrivateKey,
		FunderAddress:        creds.FunderAddress,
		APIKey:               creds.APIKey,
		APISecret:            creds.APISecret,
		APIPassphrase:        creds.APIPassphrase,
		BuilderAPIKey:        creds.BuilderAPIKey,
		BuilderAPISecret:     creds.BuilderAPISecret,
		BuilderAPIPassphrase: creds.BuilderAPIPassphrase,
	})
	session.SetCredentials(credsData)
}

func (b *Bot) runApprovalTransactions(ctx context.Context, creds *DecryptedCredentials) error {
	cfg := buildConfigFromCreds(creds)
	exec, err := executor.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to init executor: %w", err)
	}
	return exec.EnsureDefaultApprovals(ctx)
}

func (s *ApprovalState) SetPassword(value string) {
	if s.Password != nil {
		s.Password.Close()
	}
	s.Password = secureBufferFromString(value)
}

func (s *ApprovalState) SetBuilderAPIKey(value string) {
	if s.BuilderAPIKey != nil {
		s.BuilderAPIKey.Close()
	}
	s.BuilderAPIKey = secureBufferFromString(value)
}

func (s *ApprovalState) SetBuilderAPISecret(value string) {
	if s.BuilderAPISecret != nil {
		s.BuilderAPISecret.Close()
	}
	s.BuilderAPISecret = secureBufferFromString(value)
}

func (s *ApprovalState) SetBuilderAPIPassphrase(value string) {
	if s.BuilderAPIPassphrase != nil {
		s.BuilderAPIPassphrase.Close()
	}
	s.BuilderAPIPassphrase = secureBufferFromString(value)
}

func (s *ApprovalState) PasswordString() string {
	return secureBufferToString(s.Password)
}

func (s *ApprovalState) BuilderAPIKeyString() string {
	return secureBufferToString(s.BuilderAPIKey)
}

func (s *ApprovalState) BuilderAPISecretString() string {
	return secureBufferToString(s.BuilderAPISecret)
}

func (s *ApprovalState) BuilderAPIPassphraseString() string {
	return secureBufferToString(s.BuilderAPIPassphrase)
}

func (s *ApprovalState) ClearSensitive() {
	if s.Password != nil {
		s.Password.Close()
		s.Password = nil
	}
	if s.BuilderAPIKey != nil {
		s.BuilderAPIKey.Close()
		s.BuilderAPIKey = nil
	}
	if s.BuilderAPISecret != nil {
		s.BuilderAPISecret.Close()
		s.BuilderAPISecret = nil
	}
	if s.BuilderAPIPassphrase != nil {
		s.BuilderAPIPassphrase.Close()
		s.BuilderAPIPassphrase = nil
	}
}
