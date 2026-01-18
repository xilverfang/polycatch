package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/polywatch/internal/analyst"
	"github.com/polywatch/internal/apikey"
	"github.com/polywatch/internal/config"
	"github.com/polywatch/internal/executor"
	"github.com/polywatch/internal/listener"
	"github.com/polywatch/internal/storage"
	"github.com/polywatch/internal/telegram"
	"github.com/polywatch/internal/utils"
)

func main() {
	// Load .env file first (before any env var access)
	_ = config.LoadEnvFile(".env")

	// Parse command-line flags
	monitorFlag := flag.Bool("monitor", false, "Run the CLI monitor (Listener + Analyst)")
	executorFlag := flag.Bool("executor", false, "Run the CLI executor (waiting for trade signals)")
	createAPIKeyFlag := flag.Bool("create-api-key", false, "Create new API credentials programmatically")
	telegramFlag := flag.Bool("telegram", false, "Run the Telegram bot interface")
	flag.Parse()

	// Handle Telegram bot mode (completely separate flow)
	if *telegramFlag {
		runTelegramBot()
		return
	}

	// Load configuration for CLI mode
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	// Handle create-api-key flag (exit early if set)
	if *createAPIKeyFlag {
		handleCreateAPIKey(cfg)
		return
	}

	// At least one flag must be set for CLI mode
	if !*monitorFlag && !*executorFlag {
		printUsage()
		os.Exit(1)
	}

	// Display startup info
	amountFloat := new(big.Float).SetInt(cfg.MinDepositAmount)
	divisor := big.NewFloat(1_000_000)
	amountFloat.Quo(amountFloat, divisor)
	dollarAmount, _ := amountFloat.Float64()
	log.Printf("Starting Polywatch | Contract: %s | Min deposit: $%.2f", cfg.USDCContract, dollarAmount)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var listenerInstance *listener.Listener
	var analystInstance *analyst.Analyst
	var executorInstance *executor.Executor

	// Start Monitor (Listener + Analyst) if flag is set
	if *monitorFlag {
		// Create and start listener
		listenerInstance, err = listener.New(cfg)
		if err != nil {
			log.Fatalf("Listener init error: %v", err)
		}

		if err := listenerInstance.Start(ctx); err != nil {
			log.Fatalf("Listener start error: %v", err)
		}
		log.Println("Listener active | Monitoring Polygon blocks...")

		// Create analyst (G2 goroutine)
		analystInstance, err = analyst.New(cfg, listenerInstance.Deposits())
		if err != nil {
			log.Fatalf("Analyst init error: %v", err)
		}

		if err := analystInstance.Start(ctx); err != nil {
			log.Fatalf("Analyst start error: %v", err)
		}
		log.Println("Analyst active | Monitoring insider orders...")

		// Handle deposits, trade signals, and errors in goroutines
		go handleDeposits(listenerInstance)
		go handleTradeSignals(analystInstance)
		go handleErrors(listenerInstance)
		go handleAnalystErrors(analystInstance)

		// Log standalone mode message if executor is not running
		if !*executorFlag {
			log.Println("Monitor running in standalone mode. Ready to connect and send signals to executor")
		}
	}

	// Start Executor if flag is set
	if *executorFlag {
		// Validate executor requirements
		if cfg.FunderAddress == "" {
			log.Fatal("FUNDER_ADDRESS is required for executor mode")
		}

		// Create executor
		executorInstance, err = executor.New(cfg)
		if err != nil {
			log.Fatalf("Executor init error: %v", err)
		}

		// If monitor is also running, connect executor to analyst's trade signals
		if *monitorFlag && analystInstance != nil {
			if err := executorInstance.Start(ctx, analystInstance.TradeSignals()); err != nil {
				log.Fatalf("Executor start error: %v", err)
			}
			log.Println("Executor active | Connected to monitor via channel, waiting for trade signals...")
		} else {
			// Executor-only mode: use IPC to read signals from monitor running in separate process
			// Pass nil channel to trigger IPC mode
			if err := executorInstance.Start(ctx, nil); err != nil {
				log.Fatalf("Executor start error: %v", err)
			}
			log.Println("Executor active | Running in standalone mode")
			log.Println("  - Waiting for monitor to connect via Unix socket")
			log.Println("  - Monitor should be running in another terminal with: ./polywatch --monitor")
			log.Println("  - Signals will be received in real-time via IPC")
		}

		go handleExecutorErrors(executorInstance)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received | Stopping...")

	// Graceful shutdown
	if listenerInstance != nil {
		listenerInstance.Stop()
	}
	if analystInstance != nil {
		analystInstance.Stop()
	}
	if executorInstance != nil {
		executorInstance.Stop()
	}
	cancel()
	time.Sleep(500 * time.Millisecond)
	log.Println("Shutdown complete")
}

// handleDeposits processes deposit signals from the listener
func handleDeposits(listenerInstance *listener.Listener) {
	for deposit := range listenerInstance.Deposits() {
		// Convert amount to dollars
		dollarAmount := deposit.ToDollarAmount()
		dollarStr, _ := dollarAmount.Float64()

		// Format as table
		headers := []string{"Type", "Amount", "Address", "Block", "Transaction", "Time"}
		rows := [][]string{
			{
				"DEPOSIT",
				fmt.Sprintf("$%.2f", dollarStr),
				deposit.FunderAddress,
				fmt.Sprintf("%d", deposit.BlockNumber),
				deposit.TxHash,
				deposit.Timestamp.Format("15:04:05"),
			},
		}
		log.Print(utils.FormatTable(headers, rows))
	}
}

// handleTradeSignals processes trade signals from the analyst
// Trade details are already displayed by the Analyst
func handleTradeSignals(analystInstance *analyst.Analyst) {
	for range analystInstance.TradeSignals() {
		// Trade details are already logged by Analyst.displayTradeDetails()
		// Signal is automatically forwarded to Executor if it's running
		log.Println("→ Trade signal received and forwarded to executor")
	}
}

// handleErrors processes errors from the listener
func handleErrors(listenerInstance *listener.Listener) {
	for err := range listenerInstance.Errors() {
		log.Printf("ERROR | Listener: %v", err)
		// Errors are logged but don't stop the application
		// The listener handles reconnection automatically
	}
}

// handleAnalystErrors processes errors from the analyst
func handleAnalystErrors(analystInstance *analyst.Analyst) {
	for err := range analystInstance.Errors() {
		log.Printf("ERROR | Analyst: %v", err)
		// Errors are logged but don't stop the application
	}
}

// handleExecutorErrors processes errors from the executor
func handleExecutorErrors(executorInstance *executor.Executor) {
	for err := range executorInstance.Errors() {
		log.Printf("ERROR | Executor: %v", err)
		// Errors are logged but don't stop the application
	}
}

// handleCreateAPIKey creates API credentials and outputs them
func handleCreateAPIKey(cfg *config.Config) {
	log.Printf("Creating API credentials...")
	log.Println("═══════════════════════════════════════════════════════════")

	// Create API credentials
	creds, err := apikey.CreateAPIKey(context.Background(), cfg)
	if err != nil {
		log.Fatalf("Failed to create API key: %v", err)
	}

	// Output credentials
	fmt.Println("\n✅ API Credentials Created Successfully!")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("BUILDER_API_KEY=%s\n", creds.APIKey)
	fmt.Printf("BUILDER_SECRET=%s\n", creds.Secret)
	fmt.Printf("BUILDER_PASSPHRASE=%s\n", creds.Passphrase)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("\n⚠️  IMPORTANT: Save these credentials to your .env file!")
	fmt.Println("   Replace the existing BUILDER_API_KEY, BUILDER_SECRET, and BUILDER_PASSPHRASE")
}

// runTelegramBot starts the Telegram bot interface
func runTelegramBot() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println("Starting Polywatch Telegram Bot...")

	// Load bot token from environment
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable is required for --telegram mode")
	}

	// Database path (optional, defaults to ./data/polywatch.db)
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./data/polywatch.db"
	}

	// Initialize database
	dbConfig := storage.Config{
		Path:         dbPath,
		MaxOpenConns: 10,
		MaxIdleConns: 5,
	}

	db, err := storage.Open(dbConfig)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	log.Printf("Database initialized: %s", dbPath)

	// Create bot configuration
	botConfig := telegram.BotConfig{
		Token:          token,
		Debug:          os.Getenv("DEBUG") == "true",
		SessionTimeout: 30, // minutes
	}

	// Initialize bot
	bot, err := telegram.NewBot(botConfig, db)
	if err != nil {
		log.Fatalf("Failed to create bot: %v", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %v, shutting down...", sig)
		cancel()
	}()

	// Start the bot
	log.Println("Bot is running. Press Ctrl+C to stop.")
	if err := bot.Start(ctx); err != nil {
		log.Printf("Bot stopped: %v", err)
	}

	log.Println("Polywatch Telegram Bot stopped.")
}

// printUsage displays usage information
func printUsage() {
	fmt.Println(`Polywatch - Polymarket Insider Trading Monitor

Usage:
  polywatch [flags]

Modes:
  --telegram        Run the Telegram bot interface (recommended for most users)
  --monitor         Run the CLI monitor (Listener + Analyst)
  --executor        Run the CLI executor (trade execution)
  --create-api-key  Generate API credentials

Examples:
  # Run the Telegram bot (requires TELEGRAM_BOT_TOKEN env var)
  polywatch --telegram

  # Run CLI monitor and executor together
  polywatch --monitor --executor

  # Run CLI monitor in one terminal, executor in another
  Terminal 1: polywatch --monitor
  Terminal 2: polywatch --executor

  # Generate API credentials
  polywatch --create-api-key

Environment Variables:
  TELEGRAM_BOT_TOKEN   Required for --telegram mode
  DATABASE_PATH        SQLite database path (default: ./data/polywatch.db)
  POLYGON_WS_URL       Polygon WebSocket RPC URL
  SIGNER_PRIVATE_KEY   Wallet private key for signing
  FUNDER_ADDRESS       Polymarket proxy wallet address
  BUILDER_API_KEY      Polymarket API key
  BUILDER_SECRET       Polymarket API secret
  BUILDER_PASSPHRASE   Polymarket API passphrase

For more information, see: https://github.com/polywatch/polywatch`)
}
