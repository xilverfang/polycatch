package ipc

import (
	"os"
	"path/filepath"
)

// GetDefaultSocketPath returns the default Unix domain socket path
// Uses /tmp/polycatch-signals.sock on Unix systems
func GetDefaultSocketPath() string {
	// Use /tmp for Unix systems (macOS, Linux)
	// This ensures the socket is accessible and cleaned up on reboot
	return filepath.Join(os.TempDir(), "polycatch-signals.sock")
}

// EnsureSocketDir ensures the directory for the socket file exists
// Returns the socket path and any error
func EnsureSocketDir(socketPath string) (string, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return socketPath, nil
}
