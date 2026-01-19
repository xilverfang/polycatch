package listener

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/polycatch/internal/config"
	"github.com/polycatch/internal/types"
)

// Listener monitors USDC.e transfers on Polygon and emits Deposit signals
type Listener struct {
	config     *config.Config
	client     *ethclient.Client
	depositsCh chan *types.Deposit
	errorsCh   chan error
	stopCh     chan struct{}
	running    bool

	// lastProcessedBlock tracks the highest block number successfully processed.
	// It is used for catch-up after reconnects.
	lastProcessedBlock uint64

	blockTimeMu    sync.Mutex
	blockTimeCache map[uint64]time.Time
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
		// Cache block timestamps to avoid a header lookup per log (many transfers share a block).
		blockTimeCache: make(map[uint64]time.Time),
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

	// Reconnection loop: subscribe to logs via WebSocket and process them as a stream.
	// This avoids per-block FilterLogs calls (and the associated provider "invalid block range params"
	// failures), while still preserving BlockNumber/TxHash and accurate timestamps.
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopCh:
			return
		default:
		}

		if err := l.subscribeAndProcessLogs(ctx, contractAddress, transferEventHash); err != nil {
			l.errorsCh <- fmt.Errorf("error subscribing to logs: %w", err)
			time.Sleep(5 * time.Second)

			client, dialErr := ethclient.Dial(l.config.PolygonWSSURL)
			if dialErr != nil {
				l.errorsCh <- fmt.Errorf("failed to reconnect: %w", dialErr)
				time.Sleep(10 * time.Second)
				continue
			}
			if l.client != nil {
				l.client.Close()
			}
			l.client = client
		}
	}
}

func (l *Listener) subscribeAndProcessLogs(ctx context.Context, contractAddress common.Address, transferEventHash common.Hash) error {
	// On reconnect we may have missed logs; do an explicit catch-up based on lastProcessedBlock.
	// This is not a per-block polling strategy: it runs only on (re)subscribe boundaries.
	if err := l.catchUpMissedLogs(ctx, contractAddress, transferEventHash); err != nil {
		return fmt.Errorf("failed to catch up missed logs: %w", err)
	}

	logsCh := make(chan ethtypes.Log, 256)
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contractAddress},
		Topics: [][]common.Hash{
			{transferEventHash},
		},
	}

	sub, err := l.client.SubscribeFilterLogs(ctx, query, logsCh)
	if err != nil {
		return fmt.Errorf("failed to subscribe to filter logs: %w", err)
	}
	defer sub.Unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.stopCh:
			return nil
		case err := <-sub.Err():
			return fmt.Errorf("log subscription error: %w", err)
		case ev, ok := <-logsCh:
			if !ok {
				return errors.New("log subscription channel closed")
			}
			if err := l.processTransferLog(ctx, &ev); err != nil {
				// Surface the error but keep the stream alive; individual logs can fail parsing/lookup.
				l.errorsCh <- err
			}
		}
	}
}

func (l *Listener) processTransferLog(ctx context.Context, ev *ethtypes.Log) error {
	if ev == nil {
		return errors.New("log event cannot be nil")
	}
	if len(ev.Topics) < 3 {
		return nil
	}

	// Parse without a header first (timestamp set later only for relevant transfers).
	transfer, err := l.parseTransferEventFromLog(ev, nil)
	if err != nil {
		return fmt.Errorf("failed to parse transfer event from log (tx=%s idx=%d): %w", ev.TxHash.Hex(), ev.Index, err)
	}

	// Fast reject before any additional RPC calls (contract checks / timestamp lookups).
	if !transfer.IsHighValue(l.config.MinDepositAmount) {
		l.updateLastProcessedBlock(ev.BlockNumber)
		return nil
	}
	if !l.isRelevantTransfer(ctx, transfer) {
		l.updateLastProcessedBlock(ev.BlockNumber)
		return nil
	}

	ts, err := l.getBlockTimestamp(ctx, ev.BlockNumber)
	if err != nil {
		return fmt.Errorf("failed to fetch block timestamp for block %d: %w", ev.BlockNumber, err)
	}
	transfer.Timestamp = ts

	deposit := transfer.ToDeposit()
	select {
	case l.depositsCh <- deposit:
		l.updateLastProcessedBlock(ev.BlockNumber)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-l.stopCh:
		return nil
	default:
		l.updateLastProcessedBlock(ev.BlockNumber)
		return errors.New("deposits channel is full, dropping deposit")
	}
}

func (l *Listener) updateLastProcessedBlock(blockNumber uint64) {
	// Single goroutine updates in practice, but keep it correct if that changes later.
	if blockNumber > l.lastProcessedBlock {
		l.lastProcessedBlock = blockNumber
	}
}

func (l *Listener) getBlockTimestamp(ctx context.Context, blockNumber uint64) (time.Time, error) {
	l.blockTimeMu.Lock()
	if ts, ok := l.blockTimeCache[blockNumber]; ok {
		l.blockTimeMu.Unlock()
		return ts, nil
	}
	l.blockTimeMu.Unlock()

	// Retry a few times for robustness; header lookups can be transiently unavailable on some providers.
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		header, err := l.client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
		if err == nil && header != nil && header.Time > 0 {
			ts := time.Unix(int64(header.Time), 0)
			l.blockTimeMu.Lock()
			// Prevent unbounded growth; transfers are rare enough that a simple cap is sufficient.
			if len(l.blockTimeCache) > 4096 {
				l.blockTimeCache = make(map[uint64]time.Time)
			}
			l.blockTimeCache[blockNumber] = ts
			l.blockTimeMu.Unlock()
			return ts, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("header missing timestamp")
		}
		time.Sleep(time.Duration(attempt) * 150 * time.Millisecond)
	}
	return time.Time{}, lastErr
}

func (l *Listener) catchUpMissedLogs(ctx context.Context, contractAddress common.Address, transferEventHash common.Hash) error {
	// Nothing to catch up on first start.
	if l.lastProcessedBlock == 0 {
		return nil
	}

	head, err := l.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest block header: %w", err)
	}
	if head == nil || head.Number == nil {
		return errors.New("latest block header is missing number")
	}
	headNum := head.Number.Uint64()
	if headNum <= l.lastProcessedBlock {
		return nil
	}

	from := l.lastProcessedBlock + 1
	to := headNum

	// Chunk to avoid provider limits on eth_getLogs ranges.
	const maxBlockSpan uint64 = 2000
	for start := from; start <= to; {
		end := start + maxBlockSpan - 1
		if end > to {
			end = to
		}

		query := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(start),
			ToBlock:   new(big.Int).SetUint64(end),
			Addresses: []common.Address{contractAddress},
			Topics: [][]common.Hash{
				{transferEventHash},
			},
		}

		logs, err := l.client.FilterLogs(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to filter logs (from=%d to=%d): %w", start, end, err)
		}

		for i := range logs {
			ev := logs[i]
			if err := l.processTransferLog(ctx, &ev); err != nil {
				l.errorsCh <- err
			}
		}

		start = end + 1
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

	// Get block timestamp from header (if provided).
	// When streaming logs via subscription, the timestamp is populated separately using a header lookup.
	var timestamp time.Time
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
