package listener

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/polywatch/internal/config"
	"github.com/polywatch/internal/types"
)

// Listener monitors USDC.e transfers on Polygon and emits Deposit signals
type Listener struct {
	config     *config.Config
	client     *ethclient.Client
	depositsCh chan *types.Deposit
	errorsCh   chan error
	stopCh     chan struct{}
	running    bool
}

// New creates a new Listener instance
func New(cfg *config.Config) (*Listener, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	return &Listener{
		config:     cfg,
		depositsCh: make(chan *types.Deposit, 100), // Buffered channel for deposits
		errorsCh:   make(chan error, 10),           // Buffered channel for errors
		stopCh:     make(chan struct{}),
		running:    false,
	}, nil
}

// Deposits returns the channel that emits Deposit signals
func (l *Listener) Deposits() <-chan *types.Deposit {
	return l.depositsCh
}

// Errors returns the channel that emits errors
func (l *Listener) Errors() <-chan error {
	return l.errorsCh
}

// Start begins monitoring USDC.e transfers
// This should be run in a goroutine (G1 from specs)
func (l *Listener) Start(ctx context.Context) error {
	if l.running {
		return errors.New("listener is already running")
	}

	// Connect to Polygon WebSocket
	client, err := ethclient.Dial(l.config.PolygonWSSURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Polygon WebSocket: %w", err)
	}
	l.client = client
	l.running = true

	// Start monitoring in a goroutine
	go l.monitor(ctx)

	return nil
}

// Stop stops the listener
func (l *Listener) Stop() {
	if !l.running {
		return
	}
	close(l.stopCh)
	l.running = false
	if l.client != nil {
		l.client.Close()
	}
	close(l.depositsCh)
	close(l.errorsCh)
}

// monitor continuously monitors Transfer events
func (l *Listener) monitor(ctx context.Context) {
	// USDC.e contract address
	contractAddress := common.HexToAddress(l.config.USDCContract)

	// ERC20 Transfer event signature: Transfer(address indexed from, address indexed to, uint256 value)
	transferEventSig := []byte("Transfer(address,address,uint256)")
	transferEventHash := common.BytesToHash(crypto.Keccak256(transferEventSig))

	// Get the latest block to start from
	header, err := l.client.HeaderByNumber(ctx, nil)
	if err != nil {
		l.errorsCh <- fmt.Errorf("failed to get latest block: %w", err)
		return
	}
	fromBlock := header.Number

	// Reconnection loop
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
			// Monitor for new blocks
			if err := l.watchBlocks(ctx, contractAddress, transferEventHash, fromBlock); err != nil {
				l.errorsCh <- fmt.Errorf("error watching blocks: %w", err)
				// Wait before reconnecting
				time.Sleep(5 * time.Second)
				// Reconnect
				client, err := ethclient.Dial(l.config.PolygonWSSURL)
				if err != nil {
					l.errorsCh <- fmt.Errorf("failed to reconnect: %w", err)
					time.Sleep(10 * time.Second)
					continue
				}
				l.client.Close()
				l.client = client
			}
		}
	}
}

// watchBlocks watches for new blocks and processes Transfer events
func (l *Listener) watchBlocks(ctx context.Context, contractAddress common.Address, transferEventHash common.Hash, fromBlock *big.Int) error {
	// Subscribe to new block headers
	headers := make(chan *ethtypes.Header)
	sub, err := l.client.SubscribeNewHead(ctx, headers)
	if err != nil {
		return fmt.Errorf("failed to subscribe to new headers: %w", err)
	}
	defer sub.Unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.stopCh:
			return nil
		case err := <-sub.Err():
			return fmt.Errorf("subscription error: %w", err)
		case header := <-headers:
			// Process this block using event filtering (more efficient and avoids transaction type issues)
			if err := l.processBlockEvents(ctx, contractAddress, transferEventHash, header.Number); err != nil {
				l.errorsCh <- fmt.Errorf("error processing block %d: %w", header.Number.Uint64(), err)
				// Continue processing other blocks
				continue
			}
			fromBlock = header.Number
		}
	}
}

// processBlockEvents processes Transfer events in a specific block using event filtering
// This is more efficient and avoids transaction type decoding issues
func (l *Listener) processBlockEvents(ctx context.Context, contractAddress common.Address, transferEventHash common.Hash, blockNumber *big.Int) error {
	// Get block header for timestamp (without full transaction details)
	header, err := l.client.HeaderByNumber(ctx, blockNumber)
	if err != nil {
		return fmt.Errorf("failed to get block header: %w", err)
	}

	// Use FilterLogs to get Transfer events directly (avoids transaction type issues)
	query := ethereum.FilterQuery{
		FromBlock: blockNumber,
		ToBlock:   blockNumber,
		Addresses: []common.Address{contractAddress},
		Topics: [][]common.Hash{
			{transferEventHash}, // Transfer event signature
		},
	}

	logs, err := l.client.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to filter logs: %w", err)
	}

	// Process each Transfer event log
	for _, log := range logs {
		// Verify this is a Transfer event (should have 3 topics: event sig, from, to)
		if len(log.Topics) < 3 {
			continue
		}

		// Parse Transfer event
		transfer, err := l.parseTransferEventFromLog(&log, header)
		if err != nil {
			continue // Skip invalid events
		}

		// Check if transfer is to a contract address (Polymarket proxy) and is high-value
		if l.isRelevantTransfer(ctx, transfer) {
			deposit := transfer.ToDeposit()
			select {
			case l.depositsCh <- deposit:
			case <-ctx.Done():
				return ctx.Err()
			case <-l.stopCh:
				return nil
			default:
				// Channel full, log error but continue
				l.errorsCh <- errors.New("deposits channel is full, dropping deposit")
			}
		}
	}

	return nil
}

// parseTransferEventFromLog parses a Transfer event from a log (using header for timestamp)
func (l *Listener) parseTransferEventFromLog(log *ethtypes.Log, header *ethtypes.Header) (*types.Transfer, error) {
	// Transfer event: Transfer(address indexed from, address indexed to, uint256 value)
	// Topics[0] = event signature hash
	// Topics[1] = from address (indexed)
	// Topics[2] = to address (indexed)
	// Data = value (uint256)

	if len(log.Topics) < 3 {
		return nil, errors.New("invalid Transfer event: insufficient topics")
	}

	from := common.BytesToAddress(log.Topics[1].Bytes())
	to := common.BytesToAddress(log.Topics[2].Bytes())

	// Parse value from data
	if len(log.Data) < 32 {
		return nil, errors.New("invalid Transfer event: insufficient data")
	}
	value := new(big.Int).SetBytes(log.Data)

	// Get block timestamp from header
	timestamp := time.Now() // Fallback
	if header != nil && header.Time > 0 {
		timestamp = time.Unix(int64(header.Time), 0)
	}

	return &types.Transfer{
		From:            from.Hex(),
		To:              to.Hex(),
		Value:           value,
		BlockNumber:     log.BlockNumber,
		BlockHash:       log.BlockHash.Hex(),
		TransactionHash: log.TxHash.Hex(),
		LogIndex:        log.Index,
		Timestamp:       timestamp,
		ContractAddress: log.Address.Hex(),
	}, nil
}

// isRelevantTransfer checks if a transfer is relevant (high-value to a Polymarket proxy wallet)
// We monitor deposits to contract addresses that could be Polymarket proxy wallets:
// - Gnosis Safe wallets (type 2) - most common, used by MetaMask/browser wallet users
// - Polymarket Proxy wallets (type 1) - used by Magic Link (email/Google) users
// The Analyst will verify it's actually a Polymarket address via API
func (l *Listener) isRelevantTransfer(ctx context.Context, transfer *types.Transfer) bool {
	// Must be high-value
	if !transfer.IsHighValue(l.config.MinDepositAmount) {
		return false
	}

	// Check if recipient is a contract address
	// Polymarket uses two types of proxy wallets:
	// 1. Gnosis Safe (type 2) - Factory: 0xaacfeea03eb1561c4e67d661e40682bd20e3541b
	// 2. Polymarket Proxy (type 1) - Factory: 0xaB45c5A4B0c941a2F231C04C3f49182e1A254052
	// Both are contracts, so we filter for any contract address
	// The Analyst will verify it's actually a Polymarket address via API
	isContract, err := l.isContractAddress(ctx, transfer.To)
	if err != nil {
		// If we can't check, log error but don't block
		l.errorsCh <- fmt.Errorf("failed to check if address is contract: %w", err)
		return false
	}

	return isContract
}

// isContractAddress checks if an address is a contract (has code)
// Polymarket proxy wallets are contracts deployed by factory contracts:
// - Gnosis Safe wallets (most common)
// - Polymarket Proxy wallets (Magic Link users)
// Both have code, so we check for any contract address
func (l *Listener) isContractAddress(ctx context.Context, address string) (bool, error) {
	addr := common.HexToAddress(address)

	// Get code at address - if it has code, it's a contract
	code, err := l.client.CodeAt(ctx, addr, nil)
	if err != nil {
		return false, fmt.Errorf("failed to get code at address %s: %w", address, err)
	}

	// Contract addresses have code, EOA addresses have empty code
	// This catches both Gnosis Safe and Polymarket Proxy wallets
	return len(code) > 0, nil
}
