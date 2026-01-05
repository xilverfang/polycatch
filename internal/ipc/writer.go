package ipc

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/polywatch/internal/types"
)

// Writer handles writing TradeSignals to a Unix domain socket
// Maintains a persistent connection for performance
type Writer struct {
	socketPath  string
	listener    net.Listener
	conn        net.Conn
	connMutex   sync.RWMutex
	encoder     *json.Encoder
	closed      bool
	closedMutex sync.RWMutex
}

// NewWriter creates a new IPC writer that listens on the specified socket path
func NewWriter(socketPath string) *Writer {
	return &Writer{
		socketPath: socketPath,
	}
}

// Start starts the Unix domain socket server and waits for a client connection
// This should be called in a goroutine as it blocks until a connection is established
func (w *Writer) Start() error {
	// Remove existing socket file if it exists
	if err := os.RemoveAll(w.socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix domain socket listener
	listener, err := net.Listen("unix", w.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket listener: %w", err)
	}

	w.listener = listener

	// Set socket file permissions (read/write for owner only)
	if err := os.Chmod(w.socketPath, 0600); err != nil {
		log.Printf("WARNING: Failed to set socket permissions: %v", err)
	}

	log.Printf("IPC Writer | Listening on socket: %s", w.socketPath)

	// Accept connection (blocks until client connects)
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept connection: %w", err)
	}

	w.connMutex.Lock()
	w.conn = conn
	w.encoder = json.NewEncoder(conn)
	w.connMutex.Unlock()

	log.Println("IPC Writer | Executor connected, ready to send signals")

	return nil
}

// WriteSignal writes a TradeSignal to the connected client
// Returns error if connection is not established or write fails
func (w *Writer) WriteSignal(signal *types.TradeSignal) error {
	w.closedMutex.RLock()
	if w.closed {
		w.closedMutex.RUnlock()
		return fmt.Errorf("writer is closed")
	}
	w.closedMutex.RUnlock()

	w.connMutex.RLock()
	encoder := w.encoder
	conn := w.conn
	w.connMutex.RUnlock()

	if encoder == nil || conn == nil {
		return fmt.Errorf("no connection established")
	}

	// Create a serializable version of TradeSignal
	// Handle big.Int and time.Time properly
	signalJSON := convertTradeSignalToJSON(signal)

	// Write JSON with newline delimiter (JSONL format for reliability)
	if err := encoder.Encode(signalJSON); err != nil {
		// Connection might be broken, clear it
		w.connMutex.Lock()
		w.conn = nil
		w.encoder = nil
		w.connMutex.Unlock()
		return fmt.Errorf("failed to write signal: %w", err)
	}

	// Set write deadline to ensure immediate delivery
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err == nil {
		// Clear deadline after write
		conn.SetWriteDeadline(time.Time{})
	}

	return nil
}

// Stop closes the connection and cleans up the socket file
func (w *Writer) Stop() error {
	w.closedMutex.Lock()
	w.closed = true
	w.closedMutex.Unlock()

	w.connMutex.Lock()
	if w.conn != nil {
		w.conn.Close()
		w.conn = nil
		w.encoder = nil
	}
	w.connMutex.Unlock()

	if w.listener != nil {
		if err := w.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}

	// Remove socket file
	if err := os.RemoveAll(w.socketPath); err != nil {
		return fmt.Errorf("failed to remove socket file: %w", err)
	}

	log.Println("IPC Writer | Stopped and cleaned up")
	return nil
}

// IsConnected returns true if a client connection is established
func (w *Writer) IsConnected() bool {
	w.connMutex.RLock()
	defer w.connMutex.RUnlock()
	return w.conn != nil
}
