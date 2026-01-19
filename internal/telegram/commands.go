package telegram

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/polycatch/internal/executor"
	"github.com/polycatch/internal/storage"
	"github.com/polycatch/internal/types"
)

// cmdStart handles the /start command
func (b *Bot) cmdStart(ctx context.Context, chatID int64, userID int64, username string) {
	exists, _ := b.users.Exists(ctx, userID)

	var text string
	if exists {
		text = `👋 <b>Welcome back to Polywatch!</b>

You already have an account set up.

🔓 Use /unlock to start a session
📊 Use /status to check your account
⚙️ Use /settings to view your preferences
📈 Use /trades to see your trade history

Need help? Use /help for all commands.`
	} else {
		text = `🔮 <b>Welcome to Polywatch!</b>

Polywatch monitors high-value deposits on Polymarket and helps you copy insider trades with one tap.

<b>How it works:</b>
1️⃣ Set up your account with /setup
2️⃣ Unlock your session with /unlock
3️⃣ Start monitoring with /monitor
4️⃣ Get alerts when insiders trade
5️⃣ Copy trades with one button tap

<b>Security First:</b>
🔐 Your credentials are encrypted with AES-256
🔑 Only YOU know the decryption password
⏱️ Sessions auto-lock after 30 minutes
🗑️ We never store your password

Ready to start? Use /setup to create your account.`
	}

	b.sendMessage(chatID, text)
}

// cmdHelp handles the /help command
func (b *Bot) cmdHelp(ctx context.Context, chatID int64) {
	text := `📚 <b>Polywatch Commands</b>

<b>Account</b>
/setup - Create your account
/unlock - Start a session
/lock - End your session
/status - View account status
/delete - Delete your account

<b>Trading</b>
/monitor - Start monitoring for insider signals
/crypto - Trade crypto 15-min markets (BTC, ETH)
/stop - Stop monitoring
/trades - View trade history

<b>Settings</b>
/settings - View and modify settings

<b>Other</b>
/help - Show this help message
/cancel - Cancel current operation

<b>Security Tips:</b>
• Use a strong password (12+ characters)
• Never share your password with anyone
• Lock your session when not in use
• The bot will auto-lock after 30 minutes`

	b.sendMessage(chatID, text)
}

// cmdStatus handles the /status command
func (b *Bot) cmdStatus(ctx context.Context, chatID int64, userID int64) {
	// Check if user exists
	user, err := b.users.GetByTelegramID(ctx, userID)
	if err != nil {
		b.sendMessage(chatID, "❌ You don't have an account yet. Use /setup to create one.")
		return
	}

	// Check session status
	session := b.sessions.GetSession(userID)
	sessionStatus := "🔒 Locked"
	sessionExpiry := ""
	balanceStr := "🔒 <i>Unlock to view</i>"

	if session != nil && session.IsValid() {
		remaining := session.TimeRemaining()
		sessionStatus = "🔓 Unlocked"
		sessionExpiry = fmt.Sprintf(" (expires in %d min)", int(remaining.Minutes()))

		// Fetch on-chain USDC balance (funder address) when session is active
		creds, credErr := b.GetSessionCredentials(userID)
		if credErr == nil && creds != nil {
			cfg := buildConfigFromCreds(creds)
			tempExec, execErr := executor.New(cfg)
			if execErr != nil {
				balanceStr = "⚠️ <i>Failed to init executor</i>"
			} else {
				bal, balErr := tempExec.GetUSDCBalanceOnChain(ctx)
				if balErr != nil {
					balanceStr = "⚠️ <i>Failed to fetch</i>"
				} else {
					r := new(big.Rat).SetInt(bal)
					r.Quo(r, big.NewRat(1_000_000, 1))
					balanceStr = fmt.Sprintf("$%s", r.FloatString(2))
				}
			}
		}
	}

	// Get trade stats
	stats, _ := b.trades.GetStats(ctx, userID)

	text := fmt.Sprintf(`📊 <b>Account Status</b>

<b>Account</b>
👤 Username: @%s
🆔 Telegram ID: <code>%d</code>
📅 Member since: %s
🕐 Last active: %s

<b>Session</b>
%s%s

<b>Polymarket Balance</b>
💵 USDC: %s

<b>Trading Stats</b>
📈 Total trades: %d
✅ Successful: %d
❌ Failed: %d
💰 Total volume: $%.2f

<b>Settings</b>
💵 Min deposit: $%.0f
📉 Max slippage: %.1f%%
🤖 Auto-trade: %s`,
		escapeHTML(user.Username),
		user.TelegramID,
		user.CreatedAt.Format("Jan 2, 2006"),
		user.LastActiveAt.Format("Jan 2, 15:04"),
		sessionStatus, sessionExpiry,
		balanceStr,
		stats.TotalCount,
		stats.SuccessCount,
		stats.FailedCount,
		stats.SuccessAmount,
		user.Settings.MinDepositAmount,
		user.Settings.SlippageTolerance,
		boolToEmoji(user.Settings.AutoTrade),
	)

	b.sendMessage(chatID, text)
}

// cmdSettings handles the /settings command
func (b *Bot) cmdSettings(ctx context.Context, chatID int64, userID int64) {
	user, err := b.users.GetByTelegramID(ctx, userID)
	if err != nil {
		b.sendMessage(chatID, "❌ You don't have an account yet. Use /setup to create one.")
		return
	}

	text := fmt.Sprintf(`⚙️ <b>Your Settings</b>

<b>Trading Parameters</b>
💵 Min deposit alert: $%.0f
📉 Max slippage: %.1f%%
💰 Min trade amount: $%.2f
📊 Max trade %%: %d%%

<b>Automation</b>
🤖 Auto-trade: %s
🔔 Deposit alerts: %s
📨 Trade alerts: %s

<i>Tap a button below to modify:</i>`,
		user.Settings.MinDepositAmount,
		user.Settings.SlippageTolerance,
		user.Settings.MinTradeAmount,
		user.Settings.MaxTradePercent,
		boolToOnOff(user.Settings.AutoTrade),
		boolToOnOff(user.Settings.NotifyDeposits),
		boolToOnOff(user.Settings.NotifyTrades),
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💵 Min Deposit", "settings:min_deposit"),
			tgbotapi.NewInlineKeyboardButtonData("📉 Slippage", "settings:slippage"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("💰 Min Trade", "settings:min_trade"),
			tgbotapi.NewInlineKeyboardButtonData("📊 Max Trade %", "settings:max_trade"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("🤖 Auto-trade: %s", boolToOnOff(user.Settings.AutoTrade)),
				"settings:auto_trade",
			),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("🔔 Deposits: %s", boolToOnOff(user.Settings.NotifyDeposits)),
				"settings:notify_deposits",
			),
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("📨 Trades: %s", boolToOnOff(user.Settings.NotifyTrades)),
				"settings:notify_trades",
			),
		),
	)

	b.sendMessageWithKeyboard(chatID, text, keyboard)
}

func (b *Bot) cmdTrades(ctx context.Context, chatID int64, userID int64) {
	exists, _ := b.users.Exists(ctx, userID)
	if !exists {
		b.sendMessage(chatID, "❌ You don't have an account yet. Use /setup to create one.")
		return
	}

	// Check session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Please unlock your session first with /unlock")
		return
	}

	// Get monitor to access executor
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.sendMessage(chatID, "❌ Please start /monitor first to enable trading features.")
		return
	}

	positions, posErr := monitor.executor.GetActivePositions(ctx)
	activeOrders, ordersErr := monitor.executor.GetActiveOrders(ctx, "", "", "")

	// Store active order IDs for short callback data (Telegram limit: 64 bytes).
	if ordersErr == nil {
		orderIDs := make([]string, 0, len(activeOrders))
		for _, o := range activeOrders {
			if o == nil {
				continue
			}
			if strings.TrimSpace(o.ID) != "" {
				orderIDs = append(orderIDs, strings.TrimSpace(o.ID))
			}
		}
		b.tradesDashboardMu.Lock()
		b.tradesDashboard[userID] = &TradesDashboardState{
			OrderIDs:  orderIDs,
			UpdatedAt: time.Now(),
		}
		b.tradesDashboardMu.Unlock()
	}

	text := "📊 <b>Your Trading Dashboard</b>\n\n"

	// === POSITIONS SECTION ===
	text += "💼 <b>Active Positions</b>\n"
	if posErr != nil {
		text += fmt.Sprintf("<i>Unable to fetch: %s</i>\n\n", escapeHTML(posErr.Error()))
	} else if len(positions) == 0 {
		text += "<i>No active positions</i>\n\n"
	} else {
		for i, pos := range positions {
			pnlEmoji := "📈"
			if pos.CashPnL < 0 {
				pnlEmoji = "📉"
			}

			text += fmt.Sprintf(`%d. <b>%s</b> (%s)
   📊 %.2f shares @ %.1f¢ → %.1f¢
   💰 $%.2f %s <b>%+.2f</b> (%.1f%%)
`,
				i+1,
				escapeHTML(truncateString(pos.Title, 44)),
				escapeHTML(pos.Outcome),
				pos.Size,
				pos.AvgPrice*100,
				pos.CurrentPrice*100,
				pos.CurrentValue,
				pnlEmoji,
				pos.CashPnL,
				pos.PercentPnL,
			)
		}
		text += "\n"
	}

	// === ACTIVE ORDERS SECTION ===
	text += "📋 <b>Active Orders</b>\n"
	if ordersErr != nil {
		text += fmt.Sprintf("<i>Unable to fetch: %s</i>\n", escapeHTML(ordersErr.Error()))
	} else if len(activeOrders) == 0 {
		text += "<i>No active orders</i>\n"
	} else {
		for i, o := range activeOrders {
			sideEmoji := "🟢"
			if strings.ToUpper(o.Side) == "SELL" {
				sideEmoji = "🔴"
			}

			orig, _ := strconv.ParseFloat(o.OriginalSize, 64)
			matched, _ := strconv.ParseFloat(o.SizeMatched, 64)
			remaining := orig - matched
			if remaining < 0 {
				remaining = 0
			}

			price, _ := strconv.ParseFloat(o.Price, 64)

			text += fmt.Sprintf(`%d. %s <b>%s</b> • %.1f¢ • <b>%s</b>
   Remaining: %.4f / %.4f
   ID: <code>%s</code>
`,
				i+1,
				sideEmoji,
				escapeHTML(strings.ToUpper(o.Side)),
				price*100,
				escapeHTML(strings.ToUpper(o.OrderType)),
				remaining,
				orig,
				escapeHTML(truncateString(o.ID, 16)),
			)
		}
	}

	// Keyboard: sell buttons + cancel order buttons + refresh
	var keyboardRows [][]tgbotapi.InlineKeyboardButton
	if posErr == nil {
		for i := range positions {
			keyboardRows = append(keyboardRows, tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(
					fmt.Sprintf("💵 Sell Position #%d", i+1),
					fmt.Sprintf("sell:pos_%d", i),
				),
			))
		}
	}
	if ordersErr == nil {
		for i := range activeOrders {
			keyboardRows = append(keyboardRows, tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData(
					fmt.Sprintf("❌ Cancel Order #%d", i+1),
					fmt.Sprintf("trades:closeidx_%d", i),
				),
			))
		}
	}
	keyboardRows = append(keyboardRows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🔄 Refresh", "trades:refresh"),
	))

	keyboard := tgbotapi.NewInlineKeyboardMarkup(keyboardRows...)
	b.sendMessageWithKeyboard(chatID, text, keyboard)
}

// handleTradesCallback handles callbacks from the /trades command
func (b *Bot) handleTradesCallback(ctx context.Context, chatID int64, userID int64, action string, msgID int) {
	parts := strings.Split(action, "_")
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "refresh":
		b.cmdTrades(ctx, chatID, userID)

	case "close":
		if len(parts) < 2 {
			b.editMessage(chatID, msgID, "❌ Invalid order ID.")
			return
		}
		orderID := strings.Join(parts[1:], "_")
		b.handleCloseOrder(ctx, chatID, userID, orderID, msgID)

	case "closeidx":
		if len(parts) < 2 {
			b.editMessage(chatID, msgID, "❌ Invalid order selection.")
			return
		}
		idx, err := strconv.Atoi(parts[1])
		if err != nil || idx < 0 {
			b.editMessage(chatID, msgID, "❌ Invalid order selection.")
			return
		}
		b.tradesDashboardMu.RLock()
		state := b.tradesDashboard[userID]
		b.tradesDashboardMu.RUnlock()
		if state == nil || idx >= len(state.OrderIDs) {
			b.editMessage(chatID, msgID, "❌ Order list expired. Tap Refresh and try again.")
			return
		}
		b.handleCloseOrder(ctx, chatID, userID, state.OrderIDs[idx], msgID)

	case "sell":
		// Format: sell_tokenID_shares
		if len(parts) < 3 {
			b.editMessage(chatID, msgID, "❌ Invalid sell parameters.")
			return
		}
		tokenID := parts[1]
		shares, _ := strconv.ParseFloat(parts[2], 64)
		b.showSellConfirmation(ctx, chatID, userID, tokenID, shares, msgID)

	case "confirmsell":
		// Format: confirmsell_tokenID_shares_price_orderType
		if len(parts) < 5 {
			b.editMessage(chatID, msgID, "❌ Invalid sell confirmation.")
			return
		}
		tokenID := parts[1]
		shares, _ := strconv.ParseFloat(parts[2], 64)
		price, _ := strconv.ParseFloat(parts[3], 64)
		orderType := parts[4]
		b.executeSellPosition(ctx, chatID, userID, tokenID, shares, price, orderType, 0, msgID)

	default:
		b.editMessage(chatID, msgID, "❌ Unknown action.")
	}
}

// handleCloseOrder cancels an open order
func (b *Bot) handleCloseOrder(ctx context.Context, chatID int64, userID int64, orderID string, msgID int) {
	// Check session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.editMessage(chatID, msgID, "🔒 Session expired. Please /unlock again.")
		return
	}

	// Get monitor to access executor
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.editMessage(chatID, msgID, "❌ Please start /monitor first.")
		return
	}

	// Show processing message
	processingText := "⏳ <b>Cancelling order...</b>"
	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, processingText)
	editMsg.ParseMode = "HTML"
	b.api.Send(editMsg)

	// Cancel the order
	err := monitor.executor.CancelOrder(ctx, orderID)
	if err != nil {
		resultText := fmt.Sprintf(`❌ <b>Failed to Cancel Order</b>

<b>Error:</b> %s

Please try again.`, escapeHTML(err.Error()))
		editMsg := tgbotapi.NewEditMessageText(chatID, msgID, resultText)
		editMsg.ParseMode = "HTML"
		b.api.Send(editMsg)
		return
	}

	resultText := fmt.Sprintf(`✅ <b>Order Cancelled</b>

Order ID: <code>%s</code>

The order has been cancelled successfully.`, truncateString(orderID, 16))

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Refresh Positions", "trades:refresh"),
		),
	)

	editMsg = tgbotapi.NewEditMessageText(chatID, msgID, resultText)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// showSellConfirmation shows sell confirmation with order type selection
func (b *Bot) showSellConfirmation(ctx context.Context, chatID int64, userID int64, tokenID string, shares float64, msgID int) {
	// Get current price for the token
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.editMessage(chatID, msgID, "❌ Please start /monitor first.")
		return
	}

	// Fetch current price
	price, err := monitor.executor.GetCurrentPrice(ctx, tokenID)
	if err != nil {
		b.editMessage(chatID, msgID, fmt.Sprintf("❌ Failed to fetch current price: %s", escapeHTML(err.Error())))
		return
	}

	estimatedValue := shares * price

	text := fmt.Sprintf(`💵 <b>Sell Position</b>

<b>Shares:</b> %.2f
<b>Current Price:</b> %.1f¢
<b>Est. Value:</b> $%.2f

<b>Select Order Type:</b>
• <b>FAK</b> - Partial fills OK, rest cancelled
• <b>GTC</b> - Stays until filled or cancelled

⚠️ <i>Price may change at execution</i>`,
		shares,
		price*100,
		estimatedValue,
	)

	// Build callback data with parameters
	baseCallback := fmt.Sprintf("trades:confirmsell_%s_%.2f_%.4f", tokenID, shares, price)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⚡ Sell FAK", baseCallback+"_FAK"),
			tgbotapi.NewInlineKeyboardButtonData("⏰ Sell GTC", baseCallback+"_GTC"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "trades:refresh"),
		),
	)

	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// executeSellPosition executes a sell order to close a position
func (b *Bot) executeSellPosition(ctx context.Context, chatID int64, userID int64, tokenID string, shares, price float64, orderType string, expirationUnix int64, msgID int) {
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.editMessage(chatID, msgID, "❌ Please start /monitor first.")
		return
	}

	// Show processing message
	processingText := "⏳ <b>Executing sell order...</b>"
	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, processingText)
	editMsg.ParseMode = "HTML"
	b.api.Send(editMsg)

	// Execute the sell
	orderID, err := monitor.executor.SellPosition(ctx, tokenID, shares, price, orderType, expirationUnix)
	if err != nil {
		resultText := fmt.Sprintf(`❌ <b>Sell Failed</b>

<b>Error:</b> %s

Please try again.`, escapeHTML(err.Error()))
		editMsg := tgbotapi.NewEditMessageText(chatID, msgID, resultText)
		editMsg.ParseMode = "HTML"
		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("🔄 Back to Trades", "trades:refresh"),
			),
		)
		editMsg.ReplyMarkup = &keyboard
		b.api.Send(editMsg)
		return
	}

	estimatedValue := shares * price

	resultText := fmt.Sprintf(`✅ <b>Sell Order Placed!</b>

<b>Order ID:</b> <code>%s</code>
<b>Shares:</b> %.2f
<b>Price:</b> %.1f¢
<b>Type:</b> %s
<b>Est. Value:</b> $%.2f`,
		truncateString(orderID, 20),
		shares,
		price*100,
		orderType,
		estimatedValue,
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Back to Trades", "trades:refresh"),
		),
	)

	editMsg = tgbotapi.NewEditMessageText(chatID, msgID, resultText)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// cmdMonitor handles the /monitor command
func (b *Bot) cmdMonitor(ctx context.Context, chatID int64, userID int64) {
	// Check if user has an active session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Please unlock your session first with /unlock")
		return
	}

	// Check if already monitoring
	if b.monitors.IsMonitoring(userID) {
		b.sendMessage(chatID, `⚠️ <b>Already Monitoring</b>

You're already watching for insider trades.

Use /stop to stop monitoring first if you want to restart.`)
		return
	}

	// Get decrypted credentials
	creds, err := b.GetSessionCredentials(userID)
	if err != nil {
		b.sendMessage(chatID, "❌ Failed to get credentials. Please /unlock again.")
		return
	}

	// Show starting message
	startingMsgID := b.sendMessage(chatID, "⏳ <b>Starting monitor...</b>\n\nConnecting to Polygon network...")

	// Start monitoring
	if err := b.monitors.StartMonitor(ctx, userID, chatID, creds); err != nil {
		b.deleteMessage(chatID, startingMsgID)
		b.sendMessage(chatID, fmt.Sprintf("❌ <b>Failed to start monitor</b>\n\nError: %s\n\nPlease try again.", escapeHTML(err.Error())))
		return
	}

	// Delete starting message
	b.deleteMessage(chatID, startingMsgID)

	text := `🔍 <b>Monitoring Started!</b>

I'm now watching for high-value deposits on Polymarket.

<b>You'll receive alerts when:</b>
• 💰 Large deposits (>$10k) are detected
• 📊 Insiders place new trades
• 🎯 Copy opportunities arise

<b>When a trade is detected:</b>
Tap a button to instantly copy the trade with your chosen amount.

Use /stop to stop monitoring.

<i>Note: This runs in the background. You can close this chat.</i>`

	b.sendMessage(chatID, text)

	// Log the action
	b.audit.LogMonitorStart(ctx, userID)
}

// cmdStopMonitor handles the /stop command
func (b *Bot) cmdStopMonitor(ctx context.Context, chatID int64, userID int64) {
	if !b.monitors.IsMonitoring(userID) {
		b.sendMessage(chatID, "ℹ️ You're not currently monitoring.")
		return
	}

	// Stop monitoring
	b.monitors.StopMonitor(userID)

	b.sendMessage(chatID, `⏹️ <b>Monitoring Stopped</b>

You will no longer receive trade alerts.

Use /monitor to start again.`)

	b.audit.LogMonitorStop(ctx, userID)
}

// cmdDelete handles the /delete command
func (b *Bot) cmdDelete(ctx context.Context, chatID int64, userID int64) {
	exists, _ := b.users.Exists(ctx, userID)
	if !exists {
		b.sendMessage(chatID, "❌ You don't have an account to delete.")
		return
	}

	text := `⚠️ <b>Delete Account</b>

Are you sure you want to delete your account?

This will permanently delete:
• Your encrypted credentials
• All trade history
• All settings

<b>This action cannot be undone!</b>`

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🗑️ Yes, Delete Everything", "delete_confirm"),
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "delete_cancel"),
		),
	)

	b.sendMessageWithKeyboard(chatID, text, keyboard)
}

// cmdCancel handles the /cancel command
func (b *Bot) cmdCancel(ctx context.Context, chatID int64, userID int64) {
	if b.isInSetup(userID) {
		b.clearSetupState(userID)
		b.sendMessage(chatID, "❌ Setup cancelled. Your data has been cleared.\n\nUse /setup to start again.")
		return
	}

	b.sendMessage(chatID, "👍 Nothing to cancel.")
}

// handleDeleteConfirm handles the delete confirmation callback
func (b *Bot) handleDeleteConfirm(ctx context.Context, chatID int64, userID int64, messageID int) {
	// Delete user
	if err := b.users.Delete(ctx, userID); err != nil {
		b.editMessage(chatID, messageID, "❌ Failed to delete account. Please try again.")
		return
	}

	// Expire session
	b.sessions.ExpireSession(userID)

	// Log deletion (before account is gone)
	b.audit.LogAccountDelete(ctx, userID)

	b.editMessage(chatID, messageID, `✅ <b>Account Deleted</b>

Your account and all associated data have been permanently deleted.

Thank you for using Polywatch. Use /start if you ever want to return.`)
}

// handleSettingsCallback handles settings button callbacks
func (b *Bot) handleSettingsCallback(ctx context.Context, chatID int64, userID int64, setting string, messageID int) {
	user, err := b.users.GetByTelegramID(ctx, userID)
	if err != nil {
		return
	}

	settings := user.Settings

	switch setting {
	case "auto_trade":
		settings.AutoTrade = !settings.AutoTrade
	case "notify_deposits":
		settings.NotifyDeposits = !settings.NotifyDeposits
	case "notify_trades":
		settings.NotifyTrades = !settings.NotifyTrades
	default:
		// For numeric settings, we'd need a more complex flow
		b.sendMessage(chatID, "To change this setting, please enter a new value:")
		return
	}

	// Save settings
	if err := b.users.UpdateSettings(ctx, userID, settings); err != nil {
		b.sendMessage(chatID, "❌ Failed to update settings.")
		return
	}

	// Log the change
	b.audit.LogSettingsUpdate(ctx, userID, []string{setting})

	// Refresh settings display
	b.cmdSettings(ctx, chatID, userID)
}

// handleTradeCallback handles trade execution callbacks
// Callback data format: trade:action:signalID:amount
func (b *Bot) handleTradeCallback(ctx context.Context, chatID int64, userID int64, action string, data string) {
	// Check session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Session expired. Please /unlock first.")
		return
	}

	// Parse callback data - format varies by action
	// exec: signalID:amount
	// custom: signalID
	// skip: signalID
	parts := splitCallbackData(data)
	if len(parts) == 0 {
		b.sendMessage(chatID, "❌ Invalid trade data.")
		return
	}

	signalID := parts[0]

	switch action {
	case "skip":
		RemovePendingSignal(signalID)
		b.sendMessage(chatID, "⏭️ Trade skipped.")

	case "exec":
		if len(parts) < 2 {
			b.sendMessage(chatID, "❌ Invalid trade amount.")
			return
		}
		amount := parseFloat(parts[1])
		if amount <= 0 {
			b.sendMessage(chatID, "❌ Invalid trade amount.")
			return
		}
		b.executeTrade(ctx, chatID, userID, signalID, amount)

	case "custom":
		// Store the signal ID and prompt for amount
		b.customAmountMu.Lock()
		b.customAmountState[userID] = signalID
		b.customAmountMu.Unlock()

		b.sendMessage(chatID, `💰 <b>Enter Custom Amount</b>

Enter the amount in USD you want to trade (e.g., <code>75</code> or <code>150.50</code>):`)
	}
}

// executeTrade executes a trade for a user
func (b *Bot) executeTrade(ctx context.Context, chatID int64, userID int64, signalID string, amountUSD float64) {
	// Get the pending signal
	signal := GetPendingSignal(signalID)
	if signal == nil {
		b.sendMessage(chatID, "❌ Trade signal expired. Please wait for a new signal.")
		return
	}

	// Get user's monitor
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil {
		b.sendMessage(chatID, "❌ Monitor not running. Please /monitor first.")
		return
	}

	// Show executing message
	sideEmoji := "🟢"
	sideText := "BUY"
	if signal.Side == types.OrderSideSell {
		sideEmoji = "🔴"
		sideText = "SELL"
	}

	// Convert price to cents for display
	priceCents := signal.GetPriceFloat() * 100

	execMsgID := b.sendMessage(chatID, fmt.Sprintf(`⏳ <b>Executing Trade...</b>

%s %s %s @ %.1f¢
💰 Amount: $%.2f

<i>Submitting order to Polymarket...</i>`,
		sideEmoji, sideText, escapeHTML(signal.Outcome), priceCents, amountUSD))

	// Execute the trade
	result, err := monitor.ExecuteTrade(ctx, signal, amountUSD)

	// Remove pending signal
	RemovePendingSignal(signalID)

	// Delete executing message
	b.deleteMessage(chatID, execMsgID)

	if err != nil {
		// Log failed trade
		b.audit.LogTradeFailed(ctx, userID, err.Error(), signal.Market)

		b.sendMessage(chatID, fmt.Sprintf(`❌ <b>Trade Failed</b>

Error: %s

The trade was not executed. Please try again with the next signal.`, escapeHTML(err.Error())))
		return
	}

	if !result.Success {
		// Log failed trade
		b.audit.LogTradeFailed(ctx, userID, result.ErrorMessage, signal.Market)

		b.sendMessage(chatID, fmt.Sprintf(`❌ <b>Trade Failed</b>

Error: %s

The trade was not executed.`, escapeHTML(result.ErrorMessage)))
		return
	}

	// Save trade to database
	trade := &storage.Trade{
		TelegramID:     userID,
		TokenID:        signal.TokenID,
		MarketQuestion: signal.Market,
		Side:           storage.TradeSide(sideText),
		Outcome:        storage.TradeOutcome(signal.Outcome),
		Price:          signal.GetPriceFloat(),
		AmountUSD:      result.AmountUSD,
		Shares:         result.Shares,
		Status:         storage.TradeStatusSuccess,
		InsiderAddress: signal.InsiderAddress,
		InsiderAmount:  signal.InsiderAmount,
		OrderID:        result.OrderID,
		ExecutedAt:     time.Now(),
	}
	tradeID, _ := b.trades.Create(ctx, trade)

	// Log successful trade
	b.audit.LogTradeExecuted(ctx, userID, tradeID, result.AmountUSD, signal.Market)

	// Show success message with price in cents
	successPriceCents := result.Price * 100

	b.sendMessage(chatID, fmt.Sprintf(`✅ <b>Trade Executed Successfully!</b>

<b>Order ID:</b> <code>%s</code>

<b>Details:</b>
• %s %s %s @ %.1f¢
• Amount: $%.2f
• Shares: %.4f

<i>Your trade has been recorded. View history with /trades</i>`,
		escapeHTML(result.OrderID),
		sideEmoji, sideText, escapeHTML(signal.Outcome), successPriceCents,
		result.AmountUSD, result.Shares))
}

// handleCustomAmountInput handles custom amount input from user
func (b *Bot) handleCustomAmountInput(ctx context.Context, chatID int64, userID int64, text string) bool {
	b.customAmountMu.RLock()
	signalID, exists := b.customAmountState[userID]
	b.customAmountMu.RUnlock()

	if !exists {
		return false
	}

	// Parse amount
	amount := parseFloat(text)
	if amount <= 0 {
		b.sendMessage(chatID, "❌ Invalid amount. Please enter a positive number (e.g., <code>50</code>):")
		return true
	}

	if amount < 1 {
		b.sendMessage(chatID, "❌ Minimum trade amount is $1. Please enter a higher amount:")
		return true
	}

	// Clear the custom amount state
	b.customAmountMu.Lock()
	delete(b.customAmountState, userID)
	b.customAmountMu.Unlock()

	// Execute the trade
	b.executeTrade(ctx, chatID, userID, signalID, amount)
	return true
}

// splitCallbackData splits callback data by colon
func splitCallbackData(data string) []string {
	if data == "" {
		return nil
	}
	result := []string{}
	current := ""
	for _, c := range data {
		if c == ':' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// parseFloat parses a string to float64
func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

// Helper functions

func boolToEmoji(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

func boolToOnOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// (removed) fetchPolymarketBalance: we now show on-chain funder USDC balance via eth_call in executor.
