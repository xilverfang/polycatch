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
	"github.com/polywatch/internal/utils"
)

func main() {
	// Parse command-line flags
	monitorFlag := flag.Bool("monitor", false, "Run the monitor (Listener + Analyst)")
	executorFlag := flag.Bool("executor", false, "Run the executor (waiting for trade signals)")
	createAPIKeyFlag := flag.Bool("create-api-key", false, "Create new API credentials programmatically")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	// Handle create-api-key flag (exit early if set)
	if *createAPIKeyFlag {
		handleCreateAPIKey(cfg)
		return
	}

	// At least one flag must be set
	if !*monitorFlag && !*executorFlag {
		log.Fatal("Error: At least one flag must be set. Use --monitor, --executor, or --create-api-key")
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
