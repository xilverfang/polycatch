package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/polycatch/internal/types"
)

// Reader handles reading TradeSignals from a Unix domain socket
// Maintains a persistent connection for performance
type Reader struct {
	socketPath string
	conn       net.Conn
	scanner    *bufio.Scanner
	closed     bool
}

// NewReader creates a new IPC reader that connects to the specified socket path
func NewReader(socketPath string) *Reader {
	return &Reader{
		socketPath: socketPath,
	}
}

// Start connects to the Unix domain socket and starts reading signals
// This blocks until a connection is established and should be called in a goroutine
// Returns error if connection fails
func (r *Reader) Start() error {
	// Wait for socket file to exist (with retry)
	maxRetries := 30
	retryDelay := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		if _, err := os.Stat(r.socketPath); err == nil {
			break
		}
		if i < maxRetries-1 {
			log.Printf("IPC Reader | Waiting for socket at %s (attempt %d/%d)...", r.socketPath, i+1, maxRetries)
			time.Sleep(retryDelay)
		} else {
			return fmt.Errorf("socket file does not exist after %d attempts: %s", maxRetries, r.socketPath)
		}
	}

	// Connect to Unix domain socket
	conn, err := net.Dial("unix", r.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to socket: %w", err)
	}

	r.conn = conn
	r.scanner = bufio.NewScanner(conn)
	r.closed = false

	log.Printf("IPC Reader | Connected to socket: %s", r.socketPath)
	return nil
}

// ReadSignal reads the next TradeSignal from the socket
// Blocks until a signal is available or connection is closed
// Returns (signal, nil) on success, (nil, error) on failure
func (r *Reader) ReadSignal() (*types.TradeSignal, error) {
	if r.closed {
		return nil, fmt.Errorf("reader is closed")
	}

	if r.scanner == nil {
		return nil, fmt.Errorf("not connected to socket")
	}

	// Read next line (JSONL format)
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read from socket: %w", err)
		}
		// EOF - connection closed
		return nil, fmt.Errorf("connection closed by server")
	}

	// Parse JSON
	var signalJSON tradeSignalJSON
	if err := json.Unmarshal(r.scanner.Bytes(), &signalJSON); err != nil {
		return nil, fmt.Errorf("failed to parse signal JSON: %w", err)
	}

	// Convert back to TradeSignal
	signal, err := convertJSONToTradeSignal(signalJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JSON to TradeSignal: %w", err)
	}

	return signal, nil
}

// ReadSignals continuously reads signals and sends them to the provided channel
// This is a convenience method that handles the read loop
// Stops when connection is closed or Stop() is called
func (r *Reader) ReadSignals(signalChan chan<- *types.TradeSignal, errChan chan<- error) {
	defer close(signalChan)

	for !r.closed {
		signal, err := r.ReadSignal()
		if err != nil {
			if r.closed {
				return
			}
			// Connection error - send to error channel
			if errChan != nil {
				errChan <- fmt.Errorf("IPC read error: %w", err)
			}
			// Try to reconnect
			log.Println("IPC Reader | Connection lost, attempting to reconnect...")
			if err := r.reconnect(); err != nil {
				if errChan != nil {
					errChan <- fmt.Errorf("IPC reconnect failed: %w", err)
				}
				return
			}
			continue
		}

		// Send signal to channel
		select {
		case signalChan <- signal:
		case <-time.After(5 * time.Second):
			log.Println("IPC Reader | WARNING: Signal channel full, dropping signal")
		}
	}
}

// reconnect attempts to reconnect to the socket
func (r *Reader) reconnect() error {
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
		r.scanner = nil
	}

	// Wait a bit before reconnecting
	time.Sleep(2 * time.Second)

	return r.Start()
}

// Stop closes the connection
func (r *Reader) Stop() error {
	r.closed = true
	if r.conn != nil {
		if err := r.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		r.conn = nil
		r.scanner = nil
	}
	log.Println("IPC Reader | Stopped")
	return nil
}

// IsConnected returns true if connected to the socket
func (r *Reader) IsConnected() bool {
	return r.conn != nil && !r.closed
}
