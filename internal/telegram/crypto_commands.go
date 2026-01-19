package telegram

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/polycatch/internal/crypto"
	"github.com/polycatch/internal/types"
)

// CryptoTradeState holds the state for a pending crypto trade
type CryptoTradeState struct {
	Market     *crypto.BTCMarket
	Outcome    string // "up" or "down"
	Side       string // "buy" or "sell"
	TokenID    string
	Price      float64 // Current market price
	LimitPrice float64 // Custom limit price (0 = use market price)
	Amount     float64 // Selected trade amount
	OrderType  string  // "FAK", "FOK", "GTC", "GTD"
	IsLimit    bool    // Whether this is a limit order
	FetchedAt  time.Time
	MessageID  int
}

// cryptoTradeStates holds pending crypto trade states per user
var (
	cryptoTradeStates = make(map[int64]*CryptoTradeState)
	cryptoMu          sync.RWMutex
)

// setCryptoTradeState sets a user's crypto trade state
func setCryptoTradeState(userID int64, state *CryptoTradeState) {
	cryptoMu.Lock()
	defer cryptoMu.Unlock()
	cryptoTradeStates[userID] = state
}

// getCryptoTradeState gets a user's crypto trade state
func getCryptoTradeState(userID int64) *CryptoTradeState {
	cryptoMu.RLock()
	defer cryptoMu.RUnlock()
	return cryptoTradeStates[userID]
}

// clearCryptoTradeState clears a user's crypto trade state
func clearCryptoTradeState(userID int64) {
	cryptoMu.Lock()
	defer cryptoMu.Unlock()
	delete(cryptoTradeStates, userID)
}

// cmdCrypto handles the /crypto command - shows crypto market options
func (b *Bot) cmdCrypto(ctx context.Context, chatID int64, userID int64) {
	// Check if user has an active session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Please unlock your session first with /unlock")
		return
	}

	text := `📊 <b>Crypto Markets</b>

Choose a crypto asset to trade:

🟠 <b>Bitcoin (BTC)</b>
Trade 15-minute Up/Down markets

🔵 <b>Ethereum (ETH)</b>
<i>Coming soon...</i>

💡 These are short-term prediction markets where you bet on whether the price will go up or down in the next 15 minutes.`

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🟠 Bitcoin 15m", "crypto:btc15m"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔵 Ethereum (Soon)", "crypto:eth_soon"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "HTML"
	msg.ReplyMarkup = keyboard
	b.api.Send(msg)
}

// handleCryptoCallback handles crypto-related callbacks
func (b *Bot) handleCryptoCallback(ctx context.Context, chatID int64, userID int64, action string, msgID int) {
	// Check session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Session expired. Please /unlock again.")
		return
	}

	parts := strings.Split(action, "_")
	mainAction := parts[0]

	switch mainAction {
	case "btc15m":
		b.showBTC15MinMarket(ctx, chatID, userID, msgID)

	case "eth":
		b.sendMessage(chatID, "🔵 Ethereum markets coming soon!")

	case "refresh":
		// Refresh the BTC market display
		b.showBTC15MinMarket(ctx, chatID, userID, msgID)

	case "buy", "sell":
		// Format: buy_up, buy_down, sell_up, sell_down
		if len(parts) >= 2 {
			outcome := parts[1] // "up" or "down"
			b.handleCryptoTradeSetup(ctx, chatID, userID, mainAction, outcome, msgID)
		}

	case "limit":
		// Format: limit_up, limit_down
		if len(parts) >= 2 {
			outcome := parts[1] // "up" or "down"
			b.handleCryptoLimitOrderSetup(ctx, chatID, userID, outcome, msgID)
		}

	case "limitprice":
		// Format: limitprice_up, limitprice_down (from custom price input)
		if len(parts) >= 2 {
			outcome := parts[1]
			b.showLimitPriceEntry(ctx, chatID, userID, outcome, msgID)
		}

	case "amount":
		// Format: amount_10, amount_25, amount_50, amount_100, amount_custom
		if len(parts) >= 2 {
			b.handleCryptoAmountSelection(ctx, chatID, userID, parts[1], msgID)
		}

	case "ordertype":
		// Format: ordertype_FAK, ordertype_FOK, ordertype_GTC, ordertype_GTD
		if len(parts) >= 2 {
			b.handleCryptoOrderTypeSelection(ctx, chatID, userID, parts[1], msgID)
		}

	case "confirm":
		b.handleCryptoTradeConfirm(ctx, chatID, userID, msgID)

	case "cancel":
		clearCryptoTradeState(userID)
		b.editMessage(chatID, msgID, "❌ Trade cancelled.")

	case "back":
		b.showBTC15MinMarket(ctx, chatID, userID, msgID)
	}
}

// showBTC15MinMarket fetches and displays the current BTC 15-min market
func (b *Bot) showBTC15MinMarket(ctx context.Context, chatID int64, userID int64, editMsgID int) {
	fetcher := crypto.NewBTCMarketFetcher()
	market, err := fetcher.GetCurrent15MinMarket(ctx)
	if err != nil {
		log.Printf("Failed to fetch BTC market: %v", err)
		text := fmt.Sprintf("❌ Failed to fetch market: %s\n\nPlease try again in a moment.", escapeHTML(err.Error()))
		if editMsgID > 0 {
			b.editMessage(chatID, editMsgID, text)
		} else {
			b.sendMessage(chatID, text)
		}
		return
	}

	text := market.FormatForTelegram()
	text += "\n\n<b>Trade Options:</b>"

	keyboard := b.buildBTCTradeKeyboard(market)

	if editMsgID > 0 {
		editMsg := tgbotapi.NewEditMessageText(chatID, editMsgID, text)
		editMsg.ParseMode = "HTML"
		editMsg.ReplyMarkup = &keyboard
		b.api.Send(editMsg)
	} else {
		msg := tgbotapi.NewMessage(chatID, text)
		msg.ParseMode = "HTML"
		msg.ReplyMarkup = keyboard
		b.api.Send(msg)
	}
}

// buildBTCTradeKeyboard builds the inline keyboard for BTC trading
func (b *Bot) buildBTCTradeKeyboard(market *crypto.BTCMarket) tgbotapi.InlineKeyboardMarkup {
	if market.Closed || !market.AcceptingOrders {
		return tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("🔄 Refresh", "crypto:refresh"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("« Back to Crypto", "crypto:back_main"),
			),
		)
	}

	return tgbotapi.NewInlineKeyboardMarkup(
		// Buy buttons row (market orders)
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("🟢 Buy UP @ %s", market.GetUpPriceCents()),
				"crypto:buy_up",
			),
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("🔴 Buy DOWN @ %s", market.GetDownPriceCents()),
				"crypto:buy_down",
			),
		),
		// Limit order buttons row
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📊 Limit UP", "crypto:limit_up"),
			tgbotapi.NewInlineKeyboardButtonData("📊 Limit DOWN", "crypto:limit_down"),
		),
		// Refresh row
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Refresh Prices", "crypto:refresh"),
		),
		// Back row
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("« Back to Crypto", "crypto:back_main"),
		),
	)
}

// handleCryptoTradeSetup sets up a crypto trade with amount selection
func (b *Bot) handleCryptoTradeSetup(ctx context.Context, chatID int64, userID int64, side, outcome string, msgID int) {
	// Fetch fresh market data
	fetcher := crypto.NewBTCMarketFetcher()
	market, err := fetcher.GetCurrent15MinMarket(ctx)
	if err != nil {
		b.editMessage(chatID, msgID, fmt.Sprintf("❌ Failed to fetch market: %s", escapeHTML(err.Error())))
		return
	}

	if market.Closed || !market.AcceptingOrders {
		b.editMessage(chatID, msgID, "❌ This market is no longer accepting orders. Please refresh.")
		return
	}

	// Determine token ID and price based on outcome
	var tokenID string
	var price float64
	var outcomeLabel string

	if outcome == "up" {
		tokenID = market.UpTokenID
		price = market.UpPrice
		outcomeLabel = "UP 📈"
	} else {
		tokenID = market.DownTokenID
		price = market.DownPrice
		outcomeLabel = "DOWN 📉"
	}

	// Store trade state
	state := &CryptoTradeState{
		Market:    market,
		Outcome:   outcome,
		Side:      side,
		TokenID:   tokenID,
		Price:     price,
		FetchedAt: time.Now(),
		MessageID: msgID,
	}
	setCryptoTradeState(userID, state)

	sideLabel := "BUY 🟢"
	if side == "sell" {
		sideLabel = "SELL 🔴"
	}

	text := fmt.Sprintf(`💰 <b>Select Trade Amount</b>

<b>Market:</b> %s
<b>Action:</b> %s %s
<b>Price:</b> %.1f¢
<b>Balance:</b> %s

Choose an amount to trade:`,
		escapeHTML(truncateString(market.Title, 40)),
		sideLabel,
		outcomeLabel,
		price*100,
		b.getUserCollateralBalanceLine(ctx, userID),
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("$1", "crypto:amount_1"),
			tgbotapi.NewInlineKeyboardButtonData("$5", "crypto:amount_5"),
			tgbotapi.NewInlineKeyboardButtonData("$10", "crypto:amount_10"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("$25", "crypto:amount_25"),
			tgbotapi.NewInlineKeyboardButtonData("$50", "crypto:amount_50"),
			tgbotapi.NewInlineKeyboardButtonData("$100", "crypto:amount_100"),
			tgbotapi.NewInlineKeyboardButtonData("Custom", "crypto:amount_custom"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
		),
	)

	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// handleCryptoAmountSelection handles amount button clicks
func (b *Bot) handleCryptoAmountSelection(ctx context.Context, chatID int64, userID int64, amountStr string, msgID int) {
	state := getCryptoTradeState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Trade session expired. Please start again.")
		return
	}

	// Check if market data is stale (older than 30 seconds)
	if time.Since(state.FetchedAt) > 30*time.Second {
		// Refresh market data
		fetcher := crypto.NewBTCMarketFetcher()
		market, err := fetcher.GetCurrent15MinMarket(ctx)
		if err != nil {
			b.editMessage(chatID, msgID, fmt.Sprintf("❌ Failed to refresh market: %s", escapeHTML(err.Error())))
			clearCryptoTradeState(userID)
			return
		}
		state.Market = market
		if state.Outcome == "up" {
			state.TokenID = market.UpTokenID
			state.Price = market.UpPrice
		} else {
			state.TokenID = market.DownTokenID
			state.Price = market.DownPrice
		}
		state.FetchedAt = time.Now()
	}

	if amountStr == "custom" {
		// Prompt for custom amount
		text := `💵 <b>Enter Custom Amount</b>

Reply with the amount in USD (e.g., <code>15</code> or <code>75.50</code>)

Minimum: $1
Maximum: $10,000`

		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
			),
		)

		editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
		editMsg.ParseMode = "HTML"
		editMsg.ReplyMarkup = &keyboard
		b.api.Send(editMsg)
		return
	}

	// Parse amount
	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil || amount < 1 {
		b.sendMessage(chatID, "❌ Invalid amount. Please try again.")
		return
	}

	// Store amount and show order type selection
	state.Amount = amount
	setCryptoTradeState(userID, state)
	b.showCryptoOrderTypeSelection(ctx, chatID, userID, amount, msgID)
}

// showCryptoOrderTypeSelection shows order type selection screen
func (b *Bot) showCryptoOrderTypeSelection(ctx context.Context, chatID int64, userID int64, amount float64, msgID int) {
	state := getCryptoTradeState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Trade session expired. Please start again.")
		return
	}

	sideLabel := "BUY 🟢"
	if state.Side == "sell" {
		sideLabel = "SELL 🔴"
	}

	outcomeLabel := "UP 📈"
	if state.Outcome == "down" {
		outcomeLabel = "DOWN 📉"
	}

	orderKind := "Market Order"
	orderTypesHint := "Choose FAK or FOK:"
	if state.IsLimit {
		orderKind = "Limit Order"
		orderTypesHint = "Choose GTC (GTD coming soon):"
	}

	text := fmt.Sprintf(`⚙️ <b>Select Order Type</b>

<b>Market:</b> %s
<b>Action:</b> %s %s
<b>Price:</b> %.1f¢
<b>Amount:</b> $%.2f
<b>Order:</b> %s

%s`,
		escapeHTML(truncateString(state.Market.Title, 40)),
		sideLabel,
		outcomeLabel,
		state.Price*100,
		amount,
		orderKind,
		orderTypesHint,
	)

	var keyboard tgbotapi.InlineKeyboardMarkup
	if state.IsLimit {
		keyboard = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("⏰ GTC", "crypto:ordertype_GTC"),
				tgbotapi.NewInlineKeyboardButtonData("📅 GTD", "crypto:ordertype_GTD"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
			),
		)
	} else {
		keyboard = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("⚡ FAK", "crypto:ordertype_FAK"),
				tgbotapi.NewInlineKeyboardButtonData("🎯 FOK", "crypto:ordertype_FOK"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
			),
		)
	}

	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// showCryptoTradeConfirmation shows trade confirmation
func (b *Bot) showCryptoTradeConfirmation(ctx context.Context, chatID int64, userID int64, amount float64, msgID int) {
	state := getCryptoTradeState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Trade session expired. Please start again.")
		return
	}

	// Use limit price if set, otherwise market price
	tradePrice := state.Price
	if state.IsLimit && state.LimitPrice > 0 {
		tradePrice = state.LimitPrice
	}

	// Calculate shares (micro-units)
	microAmount := int64(amount * 1_000_000)
	shares := float64(microAmount) / tradePrice

	sideLabel := "BUY 🟢"
	if state.Side == "sell" {
		sideLabel = "SELL 🔴"
	}

	outcomeLabel := "UP 📈"
	if state.Outcome == "down" {
		outcomeLabel = "DOWN 📉"
	}

	orderTypeLabel := state.OrderType
	if orderTypeLabel == "" {
		if state.IsLimit {
			orderTypeLabel = "GTC"
		} else {
			orderTypeLabel = "FAK"
		}
	}

	// Build price display
	var priceDisplay string
	if state.IsLimit && state.LimitPrice > 0 {
		priceDisplay = fmt.Sprintf("%.1f¢ <i>(limit, current: %.1f¢)</i>", state.LimitPrice*100, state.Price*100)
	} else {
		priceDisplay = fmt.Sprintf("%.1f¢", state.Price*100)
	}

	orderTypeNote := ""
	if state.IsLimit {
		orderTypeNote = "\n\n📊 <b>Limit Order:</b> Will execute when price reaches your target."
	}

	text := fmt.Sprintf(`✅ <b>Confirm Trade</b>

<b>Market:</b> %s

<b>Action:</b> %s %s
<b>Price:</b> %s
<b>Amount:</b> $%.2f
<b>Order Type:</b> %s
<b>Balance:</b> %s
<b>Est. Shares:</b> ~%.0f%s

⚠️ <i>Price may change slightly at execution</i>`,
		escapeHTML(truncateString(state.Market.Title, 40)),
		sideLabel,
		outcomeLabel,
		priceDisplay,
		amount,
		orderTypeLabel,
		b.getUserCollateralBalanceLine(ctx, userID),
		shares/1_000_000,
		orderTypeNote,
	)

	// Store amount in state for confirmation
	// We'll encode it in the callback data
	confirmData := fmt.Sprintf("crypto:confirm_%s", strconv.FormatFloat(amount, 'f', 2, 64))

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Confirm Trade", confirmData),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
		),
	)

	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// handleCryptoOrderTypeSelection handles order type button clicks
func (b *Bot) handleCryptoOrderTypeSelection(ctx context.Context, chatID int64, userID int64, orderTypeStr string, msgID int) {
	state := getCryptoTradeState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Trade session expired. Please start again.")
		return
	}

	orderTypeStr = strings.ToUpper(strings.TrimSpace(orderTypeStr))

	// Validate order type based on order kind.
	if state.IsLimit {
		if orderTypeStr != "GTC" && orderTypeStr != "GTD" {
			b.editMessage(chatID, msgID, "❌ Invalid order type for limit orders. Please choose GTC.")
			return
		}
		// GTD requires a non-zero expiration timestamp. We don't collect it in the UI yet.
		if orderTypeStr == "GTD" {
			b.editMessage(chatID, msgID, "❌ GTD is not supported yet (requires expiry selection). Please choose GTC.")
			return
		}
	} else {
		if orderTypeStr != "FAK" && orderTypeStr != "FOK" {
			b.editMessage(chatID, msgID, "❌ Invalid order type for market orders. Please choose FAK or FOK.")
			return
		}
	}

	// Store order type and show confirmation
	state.OrderType = orderTypeStr
	setCryptoTradeState(userID, state)
	b.showCryptoTradeConfirmation(ctx, chatID, userID, state.Amount, msgID)
}

// handleCryptoTradeConfirm handles the final trade confirmation
func (b *Bot) handleCryptoTradeConfirm(ctx context.Context, chatID int64, userID int64, msgID int) {
	// This is called from callback - extract amount from callback data
	// The amount should be passed through the action string
}

// handleCryptoConfirmWithAmount handles trade confirmation with amount
func (b *Bot) handleCryptoConfirmWithAmount(ctx context.Context, chatID int64, userID int64, amountStr string, msgID int) {
	state := getCryptoTradeState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Trade session expired. Please start again with /crypto")
		return
	}

	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil || amount < 1 {
		b.editMessage(chatID, msgID, "❌ Invalid amount.")
		clearCryptoTradeState(userID)
		return
	}

	// Check if market is still accepting orders
	if state.Market.Closed || !state.Market.AcceptingOrders {
		b.editMessage(chatID, msgID, "❌ Market is no longer accepting orders.")
		clearCryptoTradeState(userID)
		return
	}

	// Get user's decrypted credentials
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.editMessage(chatID, msgID, "🔒 Session expired. Please /unlock again.")
		clearCryptoTradeState(userID)
		return
	}

	creds := session.GetCredentials()
	if creds == nil {
		b.editMessage(chatID, msgID, "❌ Could not access credentials. Please /unlock again.")
		clearCryptoTradeState(userID)
		return
	}

	// Show processing message
	processingText := "⏳ <b>Processing trade...</b>"
	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, processingText)
	editMsg.ParseMode = "HTML"
	b.api.Send(editMsg)

	// Get monitor for this user to execute the trade
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil {
		// Create a temporary monitor just for execution
		// First check if we can build one from credentials
		b.editMessage(chatID, msgID, "❌ Please start /monitor first to enable trading.")
		clearCryptoTradeState(userID)
		return
	}

	// Build trade signal for execution
	var side types.OrderSide
	if strings.ToUpper(state.Side) == "BUY" {
		side = types.OrderSideBuy
	} else {
		side = types.OrderSideSell
	}

	orderType := state.OrderType
	if orderType == "" {
		if state.IsLimit {
			orderType = "GTC"
		} else {
			orderType = "FAK"
		}
	}

	// Use limit price if set, otherwise use current market price
	tradePrice := state.Price
	if state.IsLimit && state.LimitPrice > 0 {
		tradePrice = state.LimitPrice
	}

	signal := &types.TradeSignal{
		TokenID: state.TokenID,
		Side:    side,
		Price:   fmt.Sprintf("%.6f", tradePrice),
		// Telegram execution overwrites Size to micro-USDC anyway (see UserMonitor.ExecuteTrade),
		// and the executor treats Size as the USDC amount to spend/receive.
		Size:        fmt.Sprintf("%.0f", amount*1_000_000),
		Market:      state.Market.Title,
		Outcome:     strings.Title(state.Outcome),
		NegRisk:     false, // BTC 15m markets are not NegRisk
		MaxSlippage: 0,     // Disabled - user decides based on displayed price
		OrderType:   orderType,
	}

	log.Printf("Executing crypto trade: TokenID=%s, Side=%s, Price=%.4f, Amount=$%.2f",
		state.TokenID, state.Side, state.Price, amount)

	// Execute the trade
	result, err := monitor.ExecuteTrade(ctx, signal, amount)

	// Clear trade state
	clearCryptoTradeState(userID)

	// Format result
	var resultText string
	if err != nil {
		resultText = fmt.Sprintf(`❌ <b>Trade Failed</b>

<b>Error:</b> %s

Please try again or check your balance.`, escapeHTML(err.Error()))
	} else if result.Success {
		resultText = fmt.Sprintf(`✅ <b>Trade Executed!</b>

<b>Market:</b> %s
<b>Action:</b> %s %s
<b>Amount:</b> $%.2f
<b>Price:</b> %.1f¢
<b>Order ID:</b> <code>%s</code>

The order has been submitted successfully.`,
			escapeHTML(truncateString(state.Market.Title, 35)),
			strings.ToUpper(state.Side),
			strings.ToUpper(state.Outcome),
			amount,
			state.Price*100,
			result.OrderID,
		)
	} else {
		resultText = fmt.Sprintf(`❌ <b>Trade Failed</b>

<b>Error:</b> %s

Please try again or check your balance.`,
			escapeHTML(result.ErrorMessage),
		)
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Trade Again", "crypto:btc15m"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("« Back to Crypto", "crypto:back_main"),
		),
	)

	finalMsg := tgbotapi.NewEditMessageText(chatID, msgID, resultText)
	finalMsg.ParseMode = "HTML"
	finalMsg.ReplyMarkup = &keyboard
	b.api.Send(finalMsg)
}

// handleCryptoLimitOrderSetup sets up a limit order with custom price entry
func (b *Bot) handleCryptoLimitOrderSetup(ctx context.Context, chatID int64, userID int64, outcome string, msgID int) {
	// Fetch fresh market data
	fetcher := crypto.NewBTCMarketFetcher()
	market, err := fetcher.GetCurrent15MinMarket(ctx)
	if err != nil {
		b.editMessage(chatID, msgID, fmt.Sprintf("❌ Failed to fetch market: %s", escapeHTML(err.Error())))
		return
	}

	if market.Closed || !market.AcceptingOrders {
		b.editMessage(chatID, msgID, "❌ This market is no longer accepting orders. Please refresh.")
		return
	}

	// Determine token ID and current price
	var tokenID string
	var currentPrice float64
	var outcomeLabel string

	if outcome == "up" {
		tokenID = market.UpTokenID
		currentPrice = market.UpPrice
		outcomeLabel = "UP 📈"
	} else {
		tokenID = market.DownTokenID
		currentPrice = market.DownPrice
		outcomeLabel = "DOWN 📉"
	}

	// Store trade state with limit order flag
	state := &CryptoTradeState{
		Market:    market,
		Outcome:   outcome,
		Side:      "buy",
		TokenID:   tokenID,
		Price:     currentPrice,
		IsLimit:   true,
		FetchedAt: time.Now(),
		MessageID: msgID,
	}
	setCryptoTradeState(userID, state)

	text := fmt.Sprintf(`📊 <b>Limit Order - %s</b>

<b>Market:</b> %s
<b>Current Price:</b> %.1f¢

Enter your desired buy price (in cents):
• Type a price like <code>45</code> for 45¢
• Price must be between 1¢ and 99¢
• Order will execute when market reaches your price

💡 <i>Buying at a lower price than current = waiting for price to drop</i>`,
		outcomeLabel,
		escapeHTML(truncateString(market.Title, 40)),
		currentPrice*100,
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
		),
	)

	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// showLimitPriceEntry is called when user needs to enter a limit price
func (b *Bot) showLimitPriceEntry(ctx context.Context, chatID int64, userID int64, outcome string, msgID int) {
	// This is handled by handleCryptoLimitOrderSetup
	b.handleCryptoLimitOrderSetup(ctx, chatID, userID, outcome, msgID)
}

// handleCryptoLimitPriceInput handles price input for limit orders
func (b *Bot) handleCryptoLimitPriceInput(ctx context.Context, chatID int64, userID int64, text string) bool {
	state := getCryptoTradeState(userID)
	if state == nil || !state.IsLimit {
		return false
	}

	// Already have a limit price? Then this is amount input
	if state.LimitPrice > 0 {
		return false
	}

	// Parse price in cents
	priceStr := strings.TrimSuffix(strings.TrimSpace(text), "¢")
	priceCents, err := strconv.ParseFloat(priceStr, 64)
	if err != nil || priceCents < 1 || priceCents > 99 {
		b.sendMessage(chatID, "❌ Invalid price. Enter a value between 1 and 99 (cents).")
		return true
	}

	// Convert cents to decimal price (e.g., 45 -> 0.45)
	limitPrice := priceCents / 100.0
	state.LimitPrice = limitPrice
	setCryptoTradeState(userID, state)

	// Now show amount selection
	b.showLimitAmountSelection(ctx, chatID, userID, state.MessageID)
	return true
}

// showLimitAmountSelection shows amount selection for limit orders
func (b *Bot) showLimitAmountSelection(ctx context.Context, chatID int64, userID int64, msgID int) {
	state := getCryptoTradeState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Trade session expired. Please start again.")
		return
	}

	outcomeLabel := "UP 📈"
	if state.Outcome == "down" {
		outcomeLabel = "DOWN 📉"
	}

	text := fmt.Sprintf(`💰 <b>Limit Order - Select Amount</b>

<b>Market:</b> %s
<b>Action:</b> BUY %s
<b>Limit Price:</b> %.1f¢ (current: %.1f¢)
<b>Balance:</b> %s

Choose an amount to trade:`,
		escapeHTML(truncateString(state.Market.Title, 40)),
		outcomeLabel,
		state.LimitPrice*100,
		state.Price*100,
		b.getUserCollateralBalanceLine(ctx, userID),
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("$1", "crypto:amount_1"),
			tgbotapi.NewInlineKeyboardButtonData("$5", "crypto:amount_5"),
			tgbotapi.NewInlineKeyboardButtonData("$10", "crypto:amount_10"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("$25", "crypto:amount_25"),
			tgbotapi.NewInlineKeyboardButtonData("$50", "crypto:amount_50"),
			tgbotapi.NewInlineKeyboardButtonData("$100", "crypto:amount_100"),
			tgbotapi.NewInlineKeyboardButtonData("Custom", "crypto:amount_custom"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "crypto:cancel"),
		),
	)

	editMsg := tgbotapi.NewEditMessageText(chatID, msgID, text)
	editMsg.ParseMode = "HTML"
	editMsg.ReplyMarkup = &keyboard
	b.api.Send(editMsg)
}

// handleCryptoCustomAmount handles custom amount text input for crypto trades
func (b *Bot) handleCryptoCustomAmount(ctx context.Context, chatID int64, userID int64, text string) bool {
	state := getCryptoTradeState(userID)
	if state == nil {
		return false
	}

	// Try to parse as amount
	amount, err := strconv.ParseFloat(strings.TrimPrefix(text, "$"), 64)
	if err != nil || amount < 1 || amount > 10000 {
		b.sendMessage(chatID, "❌ Invalid amount. Please enter a value between $1 and $10,000.")
		return true
	}

	// Show confirmation with the custom amount
	b.showCryptoTradeConfirmation(ctx, chatID, userID, amount, state.MessageID)
	return true
}

func formatUSDCFromMicro(v *big.Int) string {
	if v == nil {
		return "N/A"
	}
	r := new(big.Rat).SetInt(v)
	r.Quo(r, big.NewRat(1_000_000, 1))
	return fmt.Sprintf("$%s", r.FloatString(2))
}

func (b *Bot) getUserCollateralBalanceLine(ctx context.Context, userID int64) string {
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		return "Start /monitor to view"
	}

	bal, err := monitor.executor.GetUSDCBalanceOnChain(ctx)
	if err != nil {
		return fmt.Sprintf("Error: %s", escapeHTML(err.Error()))
	}

	return formatUSDCFromMicro(bal)
}

// SellState holds state for a pending sell order
type SellState struct {
	TokenID    string
	Shares     float64
	Price      float64 // Current market price
	LimitPrice float64 // Custom limit price (0 = market)
	IsLimit    bool
	OrderType  string // "FAK", "FOK", "GTC", "GTD"
	// ExpirationUnix is required for GTD orders (unix seconds). For non-GTD orders it should be 0.
	ExpirationUnix int64
	MarketName     string
	Outcome        string
	MessageID      int
}

var (
	sellStates = make(map[int64]*SellState)
	sellMu     sync.RWMutex
)

func setSellState(userID int64, state *SellState) {
	sellMu.Lock()
	defer sellMu.Unlock()
	sellStates[userID] = state
}

func getSellState(userID int64) *SellState {
	sellMu.RLock()
	defer sellMu.RUnlock()
	return sellStates[userID]
}

func clearSellState(userID int64) {
	sellMu.Lock()
	defer sellMu.Unlock()
	delete(sellStates, userID)
}

// cmdPositions handles the /positions command - shows user's open positions
func (b *Bot) cmdPositions(ctx context.Context, chatID int64, userID int64) {
	// Check session
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Please unlock your session first with /unlock")
		return
	}

	// Get monitor for executor access
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.sendMessage(chatID, "❌ Please start /monitor first to view positions.")
		return
	}

	// Fetch active positions
	positions, err := monitor.executor.GetActivePositions(ctx)
	if err != nil {
		b.sendMessage(chatID, fmt.Sprintf("❌ Failed to fetch positions: %s", escapeHTML(err.Error())))
		return
	}

	if len(positions) == 0 {
		b.sendMessage(chatID, `📊 <b>Your Positions</b>

You don't have any open positions.

Use /crypto to start trading!`)
		return
	}

	// Build positions list with sell buttons
	var sb strings.Builder
	sb.WriteString("📊 <b>Your Positions</b>\n")
	sb.WriteString(fmt.Sprintf("💵 USDC Balance: %s\n\n", b.getUserCollateralBalanceLine(ctx, userID)))

	var buttons [][]tgbotapi.InlineKeyboardButton
	for i, pos := range positions {
		if pos.Size < 0.01 {
			continue // Skip dust
		}

		value := pos.Size * pos.CurrentPrice
		pnl := pos.Size * (pos.CurrentPrice - pos.AvgPrice)
		pnlEmoji := "📈"
		if pnl < 0 {
			pnlEmoji = "📉"
		}

		pnlPercent := 0.0
		if value > 0 {
			pnlPercent = (pnl / value) * 100
		}

		sb.WriteString(fmt.Sprintf(`<b>%d. %s</b>
   Shares: %.2f @ avg %.1f¢
   Current: %.1f¢
   Value: $%.2f %s %.2f%%
`,
			i+1,
			escapeHTML(truncateString(pos.Title, 35)),
			pos.Size,
			pos.AvgPrice*100,
			pos.CurrentPrice*100,
			value,
			pnlEmoji,
			pnlPercent,
		))

		// Add sell button for this position
		buttons = append(buttons, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("🔴 Sell %s", truncateString(pos.Title, 20)),
				fmt.Sprintf("sell:pos_%d", i),
			),
		))
	}

	sb.WriteString("\n<i>Tap a position to sell</i>")

	// Add refresh button
	buttons = append(buttons, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🔄 Refresh", "sell:refresh"),
	))

	keyboard := tgbotapi.NewInlineKeyboardMarkup(buttons...)

	msg := tgbotapi.NewMessage(chatID, sb.String())
	msg.ParseMode = "HTML"
	msg.ReplyMarkup = keyboard
	b.api.Send(msg)
}

// handleSellCallback handles sell-related callbacks
func (b *Bot) handleSellCallback(ctx context.Context, chatID int64, userID int64, action string, msgID int) {
	session := b.sessions.GetSession(userID)
	if session == nil || !session.IsValid() {
		b.sendMessage(chatID, "🔒 Session expired. Please /unlock again.")
		return
	}

	parts := strings.Split(action, "_")
	mainAction := parts[0]

	switch mainAction {
	case "refresh":
		b.cmdPositions(ctx, chatID, userID)

	case "pos":
		// Format: pos_0, pos_1, etc.
		if len(parts) >= 2 {
			idx, err := strconv.Atoi(parts[1])
			if err != nil {
				b.editMessage(chatID, msgID, "❌ Invalid position.")
				return
			}
			b.showSellOptions(ctx, chatID, userID, idx, msgID)
		}

	case "market":
		// Market sell - expects order type as second part: market_FAK or market_FOK
		if len(parts) < 2 {
			b.editMessage(chatID, msgID, "❌ Invalid market sell request.")
			return
		}
		b.handleMarketSell(ctx, chatID, userID, strings.ToUpper(strings.TrimSpace(parts[1])), msgID)

	case "limit":
		// Limit sell - expects order type as second part: limit_GTC or limit_GTD
		if len(parts) < 2 {
			b.editMessage(chatID, msgID, "❌ Invalid limit sell request.")
			return
		}
		orderType := strings.ToUpper(strings.TrimSpace(parts[1]))
		state := getSellState(userID)
		if state == nil {
			b.editMessage(chatID, msgID, "❌ Sell session expired. Please start again from /trade.")
			return
		}
		if orderType != "GTC" && orderType != "GTD" {
			b.editMessage(chatID, msgID, "❌ Invalid limit order type. Choose GTC or GTD.")
			return
		}
		state.OrderType = orderType
		setSellState(userID, state)
		b.showLimitSellPriceEntry(ctx, chatID, userID, msgID)

	case "confirm":
		b.executeSellOrder(ctx, chatID, userID, msgID)

	case "expiry":
		// sell:expiry_<seconds>
		if len(parts) < 2 {
			b.editMessage(chatID, msgID, "❌ Invalid expiry selection.")
			return
		}
		secs, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || secs <= 0 {
			b.editMessage(chatID, msgID, "❌ Invalid expiry selection.")
			return
		}
		state := getSellState(userID)
		if state == nil {
			b.editMessage(chatID, msgID, "❌ Sell session expired. Please start again from /trade.")
			return
		}
		state.ExpirationUnix = time.Now().Unix() + secs
		setSellState(userID, state)
		b.showLimitSellConfirmation(ctx, chatID, userID, msgID)

	case "cancel":
		clearSellState(userID)
		b.editMessage(chatID, msgID, "❌ Sell cancelled.")
	}
}

func (b *Bot) showLimitSellConfirmation(ctx context.Context, chatID int64, userID int64, msgID int) {
	state := getSellState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Sell session expired. Please start again from /trade.")
		return
	}
	if !state.IsLimit || state.LimitPrice <= 0 {
		b.editMessage(chatID, msgID, "❌ Missing limit price. Please try again.")
		return
	}

	orderType := state.OrderType
	if orderType == "" {
		orderType = "GTC"
	}

	expiryLine := "∞ (GTC)"
	if orderType == "GTD" {
		if state.ExpirationUnix <= 0 {
			b.editMessage(chatID, msgID, "❌ Missing expiry for GTD. Please choose an expiry.")
			return
		}
		expiryLine = fmt.Sprintf("%d", state.ExpirationUnix)
	}

	value := state.Shares * state.LimitPrice

	confirmText := fmt.Sprintf(`✅ <b>Confirm Limit Sell</b>

<b>Market:</b> %s
<b>Selling:</b> %.2f shares
<b>Limit Price:</b> %.1f¢
<b>Current Price:</b> %.1f¢
<b>Order Type:</b> %s
<b>Expiry:</b> %s
<b>Est. Proceeds:</b> $%.2f

📊 <i>Limit order will execute when price reaches %.1f¢ or higher.</i>`,
		escapeHTML(truncateString(state.MarketName, 40)),
		state.Shares,
		state.LimitPrice*100,
		state.Price*100,
		escapeHTML(orderType),
		escapeHTML(expiryLine),
		value,
		state.LimitPrice*100,
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Confirm Sell", "sell:confirm"),
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "sell:cancel"),
		),
	)

	edit := tgbotapi.NewEditMessageText(chatID, msgID, confirmText)
	edit.ParseMode = "HTML"
	edit.ReplyMarkup = &keyboard
	b.api.Send(edit)
}

// showSellOptions shows sell options for a specific position
func (b *Bot) showSellOptions(ctx context.Context, chatID int64, userID int64, posIdx int, msgID int) {
	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.editMessage(chatID, msgID, "❌ Monitor not running. Start /monitor first.")
		return
	}

	positions, err := monitor.executor.GetActivePositions(ctx)
	if err != nil {
		b.editMessage(chatID, msgID, fmt.Sprintf("❌ Failed to fetch positions: %s", escapeHTML(err.Error())))
		return
	}

	if posIdx < 0 || posIdx >= len(positions) {
		b.editMessage(chatID, msgID, "❌ Position not found. Please refresh.")
		return
	}

	pos := positions[posIdx]

	// Get current sell price
	sellPrice, err := monitor.executor.GetCurrentPrice(ctx, pos.TokenID)
	if err != nil {
		sellPrice = pos.CurrentPrice // Fallback to position's current price
	}

	// Store sell state
	state := &SellState{
		TokenID:    pos.TokenID,
		Shares:     pos.Size,
		Price:      sellPrice,
		MarketName: pos.Title,
		Outcome:    pos.Outcome,
		MessageID:  msgID,
	}
	setSellState(userID, state)

	value := pos.Size * sellPrice
	pnl := (sellPrice - pos.AvgPrice) / pos.AvgPrice * 100

	text := fmt.Sprintf(`🔴 <b>Sell Position</b>

<b>Market:</b> %s
<b>Outcome:</b> %s
<b>Shares:</b> %.2f
<b>Avg Price:</b> %.1f¢
<b>Current Price:</b> %.1f¢
<b>Est. Value:</b> $%.2f
<b>P&amp;L:</b> %.1f%%

Choose sell type:`,
		escapeHTML(truncateString(pos.Title, 40)),
		escapeHTML(pos.Outcome),
		pos.Size,
		pos.AvgPrice*100,
		sellPrice*100,
		value,
		pnl,
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				"⚡ Market FAK",
				"sell:market_FAK",
			),
			tgbotapi.NewInlineKeyboardButtonData(
				"🎯 Market FOK",
				"sell:market_FOK",
			),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⏰ Limit GTC", "sell:limit_GTC"),
			tgbotapi.NewInlineKeyboardButtonData("📅 Limit GTD", "sell:limit_GTD"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "sell:cancel"),
		),
	)

	edit := tgbotapi.NewEditMessageText(chatID, msgID, text)
	edit.ParseMode = "HTML"
	edit.ReplyMarkup = &keyboard
	b.api.Send(edit)
}

// handleMarketSell handles market sell confirmation
func (b *Bot) handleMarketSell(ctx context.Context, chatID int64, userID int64, orderType string, msgID int) {
	state := getSellState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Sell session expired. Please start again from /trade.")
		return
	}

	state.IsLimit = false
	state.LimitPrice = 0
	state.OrderType = orderType
	setSellState(userID, state)

	value := state.Shares * state.Price

	text := fmt.Sprintf(`✅ <b>Confirm Market Sell</b>

<b>Market:</b> %s
<b>Selling:</b> %.2f shares
<b>Price:</b> %.1f¢ (market)
<b>Order Type:</b> %s
<b>Est. Proceeds:</b> $%.2f

⚠️ <i>Market orders execute immediately at best available price.</i>`,
		escapeHTML(truncateString(state.MarketName, 40)),
		state.Shares,
		state.Price*100,
		escapeHTML(orderType),
		value,
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Confirm Sell", "sell:confirm"),
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "sell:cancel"),
		),
	)

	edit := tgbotapi.NewEditMessageText(chatID, msgID, text)
	edit.ParseMode = "HTML"
	edit.ReplyMarkup = &keyboard
	b.api.Send(edit)
}

// showLimitSellPriceEntry prompts user to enter limit price
func (b *Bot) showLimitSellPriceEntry(ctx context.Context, chatID int64, userID int64, msgID int) {
	state := getSellState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Sell session expired. Please start again from /trade.")
		return
	}

	state.IsLimit = true
	state.LimitPrice = 0
	state.ExpirationUnix = 0
	setSellState(userID, state)

	text := fmt.Sprintf(`📊 <b>Limit Sell - Enter Price</b>

<b>Market:</b> %s
<b>Shares:</b> %.2f
<b>Current Price:</b> %.1f¢

Enter your limit price in cents (e.g., <code>55</code> for 55¢):`,
		escapeHTML(truncateString(state.MarketName, 40)),
		state.Shares,
		state.Price*100,
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "sell:cancel"),
		),
	)

	edit := tgbotapi.NewEditMessageText(chatID, msgID, text)
	edit.ParseMode = "HTML"
	edit.ReplyMarkup = &keyboard
	b.api.Send(edit)
}

// handleLimitSellPriceInput handles text input for limit sell price
func (b *Bot) handleLimitSellPriceInput(ctx context.Context, chatID int64, userID int64, text string) bool {
	state := getSellState(userID)
	if state == nil || !state.IsLimit {
		return false
	}

	// Already have limit price? Not a price input
	if state.LimitPrice > 0 {
		return false
	}

	// Parse the price (in cents)
	priceCents, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	if err != nil || priceCents <= 0 || priceCents > 100 {
		b.sendMessage(chatID, "❌ Invalid price. Enter a number between 1 and 99 (cents).")
		return true
	}

	limitPrice := priceCents / 100.0
	state.LimitPrice = limitPrice
	setSellState(userID, state)

	// For GTD we need an expiry selection before confirmation.
	if state.OrderType == "GTD" && state.ExpirationUnix <= 0 {
		text := fmt.Sprintf(`📅 <b>Limit Sell (GTD) - Choose Expiry</b>

<b>Market:</b> %s
<b>Limit Price:</b> %.1f¢

Select how long this order should remain open:`,
			escapeHTML(truncateString(state.MarketName, 40)),
			state.LimitPrice*100,
		)

		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("1h", "sell:expiry_3600"),
				tgbotapi.NewInlineKeyboardButtonData("6h", "sell:expiry_21600"),
				tgbotapi.NewInlineKeyboardButtonData("24h", "sell:expiry_86400"),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("7d", "sell:expiry_604800"),
				tgbotapi.NewInlineKeyboardButtonData("❌ Cancel", "sell:cancel"),
			),
		)

		edit := tgbotapi.NewEditMessageText(chatID, state.MessageID, text)
		edit.ParseMode = "HTML"
		edit.ReplyMarkup = &keyboard
		b.api.Send(edit)
		return true
	}

	b.showLimitSellConfirmation(ctx, chatID, userID, state.MessageID)

	return true
}

// executeSellOrder executes the sell order
func (b *Bot) executeSellOrder(ctx context.Context, chatID int64, userID int64, msgID int) {
	state := getSellState(userID)
	if state == nil {
		b.editMessage(chatID, msgID, "❌ Sell session expired. Please start again from /trade.")
		return
	}

	monitor := b.monitors.GetMonitor(userID)
	if monitor == nil || monitor.executor == nil {
		b.editMessage(chatID, msgID, "❌ Monitor not running. Start /monitor first.")
		clearSellState(userID)
		return
	}

	b.editMessage(chatID, msgID, "⏳ Executing sell order...")

	// Determine price and order type
	price := state.Price
	orderType := strings.ToUpper(strings.TrimSpace(state.OrderType))
	if orderType == "" {
		if state.IsLimit {
			orderType = "GTC"
		} else {
			orderType = "FAK"
		}
	}

	if state.IsLimit && state.LimitPrice > 0 {
		price = state.LimitPrice
	}

	// Validate supported types by order kind
	if state.IsLimit {
		if orderType != "GTC" && orderType != "GTD" {
			b.editMessage(chatID, msgID, "❌ Invalid limit order type. Choose GTC or GTD.")
			clearSellState(userID)
			return
		}
		if orderType == "GTD" && state.ExpirationUnix <= 0 {
			b.editMessage(chatID, msgID, "❌ Missing expiry for GTD. Please select an expiry.")
			return
		}
	} else {
		if orderType != "FAK" && orderType != "FOK" {
			b.editMessage(chatID, msgID, "❌ Invalid market order type. Choose FAK or FOK.")
			clearSellState(userID)
			return
		}
	}

	// Execute the sell
	orderID, err := monitor.executor.SellPosition(ctx, state.TokenID, state.Shares, price, orderType, state.ExpirationUnix)
	if err != nil {
		b.editMessage(chatID, msgID, fmt.Sprintf(`❌ <b>Sell Failed</b>

<b>Error:</b> %s

Please try again.`, escapeHTML(err.Error())))
		clearSellState(userID)
		return
	}

	orderTypeLabel := orderType

	text := fmt.Sprintf(`✅ <b>Sell Order Submitted</b>

<b>Order ID:</b> <code>%s</code>
<b>Type:</b> %s
<b>Shares:</b> %.2f
<b>Price:</b> %.1f¢
<b>Est. Proceeds:</b> $%.2f

Your order has been submitted to Polymarket.`,
		orderID,
		escapeHTML(orderTypeLabel),
		state.Shares,
		price*100,
		state.Shares*price,
	)

	b.editMessage(chatID, msgID, text)
	clearSellState(userID)
}
