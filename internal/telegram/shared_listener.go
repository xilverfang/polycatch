package telegram

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/polywatch/internal/config"
	"github.com/polywatch/internal/listener"
	"github.com/polywatch/internal/types"
)

// SharedListener manages a single websocket connection shared by all monitors.
// Instead of each user having their own listener (N websockets for N users),
// we maintain one connection and broadcast deposits to all subscribers.
type SharedListener struct {
	listener    *listener.Listener
	subscribers map[int64]chan *types.Deposit // userID -> deposit channel
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	running     bool
	config      *config.Config
}

// sharedListenerInstance is the singleton shared listener
var (
	sharedListenerInstance *SharedListener
	sharedListenerOnce     sync.Once
	sharedListenerMu       sync.Mutex
)

// GetSharedListener returns the singleton shared listener instance.
// Creates it on first call using the provided config.
func GetSharedListener(cfg *config.Config) (*SharedListener, error) {
	sharedListenerMu.Lock()
	defer sharedListenerMu.Unlock()

	if sharedListenerInstance != nil {
		return sharedListenerInstance, nil
	}

	sl := &SharedListener{
		subscribers: make(map[int64]chan *types.Deposit),
		config:      cfg,
	}

	sharedListenerInstance = sl
	return sl, nil
}

// Start starts the shared listener if not already running
func (sl *SharedListener) Start(ctx context.Context) error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.running {
		return nil // Already running
	}

	// Create base listener
	baseListener, err := listener.New(sl.config)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	sl.listener = baseListener

	// Create context for listener lifecycle
	sl.ctx, sl.cancel = context.WithCancel(ctx)

	// Start the base listener
	if err := sl.listener.Start(sl.ctx); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	sl.running = true

	// Start broadcast goroutine
	go sl.broadcastLoop()
	go sl.handleErrors()

	log.Printf("SharedListener started (single websocket for all monitors)")
	return nil
}

// Stop stops the shared listener (only when no subscribers remain)
func (sl *SharedListener) Stop() {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Only stop if no subscribers
	if len(sl.subscribers) > 0 {
		log.Printf("SharedListener: %d subscribers remaining, not stopping", len(sl.subscribers))
		return
	}

	if !sl.running {
		return
	}

	sl.running = false
	if sl.listener != nil {
		sl.listener.Stop()
	}
	if sl.cancel != nil {
		sl.cancel()
	}

	log.Printf("SharedListener stopped")
}

// Subscribe adds a subscriber to receive deposits.
// Returns a channel that will receive deposit notifications.
func (sl *SharedListener) Subscribe(userID int64) <-chan *types.Deposit {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Create buffered channel for this subscriber
	ch := make(chan *types.Deposit, 100)
	sl.subscribers[userID] = ch

	log.Printf("SharedListener: user %d subscribed (%d total subscribers)", userID, len(sl.subscribers))
	return ch
}

// Unsubscribe removes a subscriber
func (sl *SharedListener) Unsubscribe(userID int64) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if ch, exists := sl.subscribers[userID]; exists {
		close(ch)
		delete(sl.subscribers, userID)
		log.Printf("SharedListener: user %d unsubscribed (%d total subscribers)", userID, len(sl.subscribers))
	}

	// If no subscribers remain, consider stopping (but keep running for quick re-subscribe)
	// In production, you might add idle timeout before stopping
}

// SubscriberCount returns the number of active subscribers
func (sl *SharedListener) SubscriberCount() int {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	return len(sl.subscribers)
}

// IsRunning returns whether the shared listener is running
func (sl *SharedListener) IsRunning() bool {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	return sl.running
}

// broadcastLoop reads deposits from the base listener and broadcasts to all subscribers
func (sl *SharedListener) broadcastLoop() {
	deposits := sl.listener.Deposits()
	for {
		select {
		case <-sl.ctx.Done():
			return
		case deposit, ok := <-deposits:
			if !ok {
				return
			}
			sl.broadcast(deposit)
		}
	}
}

// broadcast sends a deposit to all subscribers
func (sl *SharedListener) broadcast(deposit *types.Deposit) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	for userID, ch := range sl.subscribers {
		select {
		case ch <- deposit:
			// Successfully sent
		default:
			// Channel full, log warning but don't block
			log.Printf("WARNING | SharedListener: deposit channel full for user %d, dropping", userID)
		}
	}
}

// handleErrors forwards errors from the base listener
func (sl *SharedListener) handleErrors() {
	errors := sl.listener.Errors()
	for {
		select {
		case <-sl.ctx.Done():
			return
		case err, ok := <-errors:
			if !ok {
				return
			}
			log.Printf("SharedListener error: %v", err)
		}
	}
}
