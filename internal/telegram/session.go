package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/polycatch/internal/storage"
)

// DecryptedCredentials holds decrypted user credentials in memory
type DecryptedCredentials struct {
	SignerPrivateKey     string
	FunderAddress        string
	APIKey               string
	APISecret            string
	APIPassphrase        string
	BuilderAPIKey        string
	BuilderAPISecret     string
	BuilderAPIPassphrase string
}

// cmdUnlock handles the /unlock command
func (b *Bot) cmdUnlock(ctx context.Context, chatID int64, userID int64, password string) {
	// Check if user exists
	exists, _ := b.users.Exists(ctx, userID)
	if !exists {
		b.sendMessage(chatID, "❌ You don't have an account yet. Use /setup to create one.")
		return
	}

	// Check if already unlocked
	session := b.sessions.GetSession(userID)
	if session != nil && session.IsValid() {
		remaining := session.TimeRemaining()
		b.sendMessage(chatID, fmt.Sprintf(`🔓 Session already active!

Time remaining: %d minutes

Use /lock to end your session early.
Use /status to view your account.`, int(remaining.Minutes())))
		return
	}

	// If password provided as argument, use it
	password = trimPassword(password)
	if password != "" {
		b.tryUnlock(ctx, chatID, userID, password, 0)
		return
	}

	// Otherwise, prompt for password
	text := `🔐 <b>Unlock Session</b>

Enter your encryption password to unlock your session.

⚠️ <i>Your message will be deleted for security.</i>`

	b.sendMessage(chatID, text)
}

// tryUnlock attempts to unlock a session with a password
func (b *Bot) tryUnlock(ctx context.Context, chatID int64, userID int64, password string, messageID int) {
	// Delete the password message if we have the ID
	if messageID > 0 {
		b.deleteMessage(chatID, messageID)
	}

	// Check for too many failed attempts
	since := time.Now().Add(-15 * time.Minute)
	failedAttempts, _ := b.audit.GetFailedLogins(ctx, userID, since)
	if failedAttempts >= 5 {
		b.sendMessage(chatID, `🔒 <b>Account Temporarily Locked</b>

Too many failed login attempts. Please wait 15 minutes before trying again.

If you forgot your password, you'll need to /delete your account and /setup again.`)
		return
	}

	// Try to decrypt credentials
	creds, err := b.users.DecryptCredentials(ctx, userID, password)
	if err != nil {
		log.Printf("Unlock failed for user %d: %v", userID, err)

		// Log failed attempt
		b.audit.LogLoginFailed(ctx, userID, "invalid_password")

		remainingAttempts := 5 - failedAttempts - 1
		if remainingAttempts <= 0 {
			b.sendMessage(chatID, `❌ <b>Invalid password</b>

Account temporarily locked. Please wait 15 minutes.`)
		} else {
			b.sendMessage(chatID, fmt.Sprintf(`❌ <b>Invalid password</b>

%d attempts remaining before temporary lockout.

Try again or use /cancel.`, remainingAttempts))
		}
		return
	}

	// Create session and store decrypted credentials
	session := b.sessions.CreateSession(userID)

	// Serialize credentials for session storage
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

	// Update last active
	b.users.UpdateLastActive(ctx, userID)

	// Log successful login
	b.audit.LogLogin(ctx, userID)

	timeout := b.config.SessionTimeout
	if timeout == 0 {
		timeout = 30
	}

	text := fmt.Sprintf(`🔓 <b>Session Unlocked!</b>

Your session is now active for %d minutes.

<b>Available commands:</b>
• /monitor - Start watching for trades
• /status - View your account
• /settings - Modify preferences
• /trades - View trade history
• /crypto - Trade crypto 15-min markets
• /lock - End session early

Happy trading! 📈`, timeout)

	b.sendMessage(chatID, text)
}

// cmdLock handles the /lock command
func (b *Bot) cmdLock(ctx context.Context, chatID int64, userID int64) {
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 No active session to lock.")
		return
	}

	// Expire the session
	b.sessions.ExpireSession(userID)

	// Log logout
	b.audit.LogLogout(ctx, userID)

	b.sendMessage(chatID, `🔒 <b>Session Locked</b>

Your credentials have been cleared from memory.

Use /unlock to start a new session.`)
}

// GetSessionCredentials retrieves decrypted credentials from an active session
func (b *Bot) GetSessionCredentials(userID int64) (*DecryptedCredentials, error) {
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		return nil, storage.ErrSessionExpired
	}

	credsData := session.GetCredentials()
	if credsData == nil {
		return nil, storage.ErrSessionExpired
	}

	var creds DecryptedCredentials
	if err := json.Unmarshal(credsData, &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	return &creds, nil
}

// RefreshSession extends the session timeout
func (b *Bot) RefreshSession(userID int64) {
	session := b.sessions.GetSession(userID)
	if session != nil && session.IsValid() {
		timeout := time.Duration(b.config.SessionTimeout) * time.Minute
		if timeout == 0 {
			timeout = 30 * time.Minute
		}
		session.Refresh(timeout)
	}
}

// IsSessionActive checks if a user has an active session
func (b *Bot) IsSessionActive(userID int64) bool {
	session := b.sessions.GetSession(userID)
	return session != nil && session.IsValid()
}

// trimPassword safely trims password input
func trimPassword(s string) string {
	// Use a simple approach that doesn't create extra string copies
	start := 0
	end := len(s)

	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	if start == 0 && end == len(s) {
		return s
	}
	return s[start:end]
}

// SessionInfo provides information about a session for display
type SessionInfo struct {
	IsActive      bool
	TimeRemaining time.Duration
	UnlockedAt    time.Time
}

// GetSessionInfo returns information about a user's session
func (b *Bot) GetSessionInfo(userID int64) *SessionInfo {
	session := b.sessions.GetSession(userID)
	if session == nil {
		return &SessionInfo{IsActive: false}
	}

	return &SessionInfo{
		IsActive:      session.IsValid(),
		TimeRemaining: session.TimeRemaining(),
	}
}

// NotifySessionExpiring sends a warning before session expires
func (b *Bot) NotifySessionExpiring(chatID int64, userID int64, minutesRemaining int) {
	text := fmt.Sprintf(`⏰ <b>Session Expiring Soon</b>

Your session will expire in %d minutes.

Send any message or use /unlock to extend your session.`, minutesRemaining)

	b.sendMessage(chatID, text)
}

// StartSessionExpiryNotifier starts a goroutine that notifies users before session expires
func (b *Bot) StartSessionExpiryNotifier(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// This would iterate active sessions and notify users
			// when their session is about to expire (e.g., 5 minutes left)
			// Implementation depends on how we track chatIDs for users
		}
	}
}

// ValidateAndRefreshSession validates a session and refreshes if valid
// Returns the credentials if valid, error otherwise
func (b *Bot) ValidateAndRefreshSession(ctx context.Context, userID int64) (*DecryptedCredentials, error) {
	creds, err := b.GetSessionCredentials(userID)
	if err != nil {
		return nil, err
	}

	// Refresh session on activity
	b.RefreshSession(userID)

	// Update last active in database
	b.users.UpdateLastActive(ctx, userID)

	return creds, nil
}
