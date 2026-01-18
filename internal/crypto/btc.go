// Package crypto provides functionality for trading crypto markets on Polymarket.
package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	// GammaAPIURL is the base URL for Polymarket's Gamma API
	GammaAPIURL = "https://gamma-api.polymarket.com"
	// CLOBAPIURL is the base URL for Polymarket's CLOB API (used for live prices)
	CLOBAPIURL = "https://clob.polymarket.com"

	// Market intervals in seconds
	Interval15Min = 900
)

// BTCMarket represents a Bitcoin Up/Down 15-minute market
type BTCMarket struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Slug            string    `json:"slug"`
	Timestamp       int64     // Unix timestamp for the market
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	UpTokenID       string    `json:"up_token_id"`
	DownTokenID     string    `json:"down_token_id"`
	UpPrice         float64   `json:"up_price"`
	DownPrice       float64   `json:"down_price"`
	AcceptingOrders bool      `json:"accepting_orders"`
	NegRisk         bool      `json:"neg_risk"`
	Volume          float64   `json:"volume"`
	Liquidity       float64   `json:"liquidity"`
	BestBid         float64   `json:"best_bid"`
	BestAsk         float64   `json:"best_ask"`
	Closed          bool      `json:"closed"`
}

// gammaEventResponse represents the API response structure
type gammaEventResponse struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Slug    string  `json:"slug"`
	Closed  bool    `json:"closed"`
	NegRisk bool    `json:"negRisk"`
	Volume  float64 `json:"volume"`
	Markets []struct {
		ID              string  `json:"id"`
		Question        string  `json:"question"`
		ClobTokenIds    string  `json:"clobTokenIds"`  // JSON array as string
		OutcomePrices   string  `json:"outcomePrices"` // JSON array as string
		AcceptingOrders bool    `json:"acceptingOrders"`
		NegRisk         bool    `json:"negRisk"`
		Volume          string  `json:"volume"`
		Liquidity       string  `json:"liquidity"`
		BestBid         float64 `json:"bestBid"`
		BestAsk         float64 `json:"bestAsk"`
		Closed          bool    `json:"closed"`
		EndDate         string  `json:"endDate"`
		EventStartTime  string  `json:"eventStartTime"`
	} `json:"markets"`
}

// BTCMarketFetcher fetches Bitcoin 15-minute markets from Polymarket
type BTCMarketFetcher struct {
	httpClient *http.Client
}

// NewBTCMarketFetcher creates a new BTC market fetcher
func NewBTCMarketFetcher() *BTCMarketFetcher {
	return &BTCMarketFetcher{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type clobPriceResponse struct {
	Price any `json:"price"`
}

func parseCLOBPrice(body []byte) (float64, error) {
	var res clobPriceResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return 0, fmt.Errorf("failed to parse CLOB price response: %w", err)
	}

	switch v := res.Price.(type) {
	case string:
		price, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("CLOB price is not a float string (got %q): %w", v, err)
		}
		return price, nil
	case float64:
		return v, nil
	case nil:
		return 0, fmt.Errorf("CLOB price missing in response: %s", string(body))
	default:
		return 0, fmt.Errorf("CLOB price has unsupported type %T in response: %s", v, string(body))
	}
}

// fetchLivePrice fetches a live price from the CLOB API for a token.
// We use side=BUY to match what users see when buying on the web UI.
func (f *BTCMarketFetcher) fetchLivePrice(ctx context.Context, tokenID string) (float64, error) {
	url := fmt.Sprintf("%s/price?token_id=%s&side=BUY", CLOBAPIURL, tokenID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create CLOB price request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch CLOB price: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read CLOB price response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CLOB price API returned status %d: %s", resp.StatusCode, string(body))
	}

	return parseCLOBPrice(body)
}

// GetCurrent15MinMarket fetches the current active 15-minute BTC market
func (f *BTCMarketFetcher) GetCurrent15MinMarket(ctx context.Context) (*BTCMarket, error) {
	// Calculate the current 15-minute interval timestamp
	now := time.Now().Unix()
	currentInterval := (now / Interval15Min) * Interval15Min

	// Try current interval first, then next if current is closed
	market, err := f.fetch15MinMarket(ctx, currentInterval)
	if err != nil {
		return nil, err
	}

	// If current market is closed or not accepting orders, try the next one
	if market.Closed || !market.AcceptingOrders {
		nextInterval := currentInterval + Interval15Min
		market, err = f.fetch15MinMarket(ctx, nextInterval)
		if err != nil {
			return nil, err
		}
	}

	return market, nil
}

// GetNext15MinMarket fetches the next 15-minute BTC market
func (f *BTCMarketFetcher) GetNext15MinMarket(ctx context.Context) (*BTCMarket, error) {
	now := time.Now().Unix()
	nextInterval := ((now / Interval15Min) + 1) * Interval15Min
	return f.fetch15MinMarket(ctx, nextInterval)
}

// GetMarketByTimestamp fetches a specific 15-minute market by timestamp
func (f *BTCMarketFetcher) GetMarketByTimestamp(ctx context.Context, timestamp int64) (*BTCMarket, error) {
	return f.fetch15MinMarket(ctx, timestamp)
}

// fetch15MinMarket fetches a 15-minute market by timestamp
func (f *BTCMarketFetcher) fetch15MinMarket(ctx context.Context, timestamp int64) (*BTCMarket, error) {
	slug := fmt.Sprintf("btc-updown-15m-%d", timestamp)
	url := fmt.Sprintf("%s/events/slug/%s", GammaAPIURL, slug)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch market: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("market not found for timestamp %d", timestamp)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var event gammaEventResponse
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(event.Markets) == 0 {
		return nil, fmt.Errorf("no markets found in response")
	}

	market := event.Markets[0]

	// Parse token IDs (JSON array as string)
	var tokenIds []string
	if err := json.Unmarshal([]byte(market.ClobTokenIds), &tokenIds); err != nil {
		return nil, fmt.Errorf("failed to parse token IDs: %w", err)
	}
	if len(tokenIds) < 2 {
		return nil, fmt.Errorf("expected 2 token IDs, got %d", len(tokenIds))
	}

	// Parse prices (JSON array as string)
	var prices []string
	if err := json.Unmarshal([]byte(market.OutcomePrices), &prices); err != nil {
		return nil, fmt.Errorf("failed to parse prices: %w", err)
	}

	upPrice := 0.0
	downPrice := 0.0
	if len(prices) >= 2 {
		upPrice, _ = strconv.ParseFloat(prices[0], 64)
		downPrice, _ = strconv.ParseFloat(prices[1], 64)
	}

	// Override Gamma prices with live prices from CLOB so refresh matches the web UI.
	liveUp, err := f.fetchLivePrice(ctx, tokenIds[0])
	if err != nil {
		return nil, fmt.Errorf("failed to fetch live UP price (token %s): %w", tokenIds[0], err)
	}
	liveDown, err := f.fetchLivePrice(ctx, tokenIds[1])
	if err != nil {
		return nil, fmt.Errorf("failed to fetch live DOWN price (token %s): %w", tokenIds[1], err)
	}
	upPrice = liveUp
	downPrice = liveDown

	volume, _ := strconv.ParseFloat(market.Volume, 64)
	liquidity, _ := strconv.ParseFloat(market.Liquidity, 64)

	// Parse times
	var endTime, startTime time.Time
	if market.EndDate != "" {
		endTime, _ = time.Parse(time.RFC3339, market.EndDate)
	}
	if market.EventStartTime != "" {
		startTime, _ = time.Parse(time.RFC3339, market.EventStartTime)
	}

	return &BTCMarket{
		ID:              market.ID,
		Title:           event.Title,
		Slug:            event.Slug,
		Timestamp:       timestamp,
		StartTime:       startTime,
		EndTime:         endTime,
		UpTokenID:       tokenIds[0],
		DownTokenID:     tokenIds[1],
		UpPrice:         upPrice,
		DownPrice:       downPrice,
		AcceptingOrders: market.AcceptingOrders,
		NegRisk:         market.NegRisk,
		Volume:          volume,
		Liquidity:       liquidity,
		BestBid:         market.BestBid,
		BestAsk:         market.BestAsk,
		Closed:          market.Closed,
	}, nil
}

// FormatForTelegram returns a formatted string for Telegram display
func (m *BTCMarket) FormatForTelegram() string {
	status := "🟢 Active"
	if m.Closed {
		status = "🔴 Closed"
	} else if !m.AcceptingOrders {
		status = "🟡 Not Accepting Orders"
	}

	timeLeft := ""
	if !m.EndTime.IsZero() {
		remaining := time.Until(m.EndTime)
		if remaining > 0 {
			timeLeft = fmt.Sprintf("\n⏱ Time left: %s", formatDuration(remaining))
		}
	}

	return fmt.Sprintf(`📈 <b>Bitcoin 15-Min Market</b>

<b>%s</b>

%s%s

💰 <b>Current Prices:</b>
   🟢 Up: <b>%.1f¢</b>
   🔴 Down: <b>%.1f¢</b>

📊 Volume: $%.2f
💧 Liquidity: $%.2f`,
		m.Title,
		status,
		timeLeft,
		m.UpPrice*100,
		m.DownPrice*100,
		m.Volume,
		m.Liquidity,
	)
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// GetUpPriceCents returns the Up price in cents
func (m *BTCMarket) GetUpPriceCents() string {
	return fmt.Sprintf("%.1f¢", m.UpPrice*100)
}

// GetDownPriceCents returns the Down price in cents
func (m *BTCMarket) GetDownPriceCents() string {
	return fmt.Sprintf("%.1f¢", m.DownPrice*100)
}
