package crypto

import (
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// SecureBuffer is a buffer that securely clears its contents when done.
// Use this for storing sensitive data like passwords and keys in memory.
//
// Security features:
// - Automatic zeroing when Close() is called
// - Finalizer to catch forgotten Close() calls
// - No copying of underlying data
type SecureBuffer struct {
	data      []byte
	mu        sync.Mutex
	closed    bool
	finalizer bool
}

// NewSecureBuffer creates a new secure buffer with the given capacity.
// The buffer should be closed when no longer needed to clear sensitive data.
func NewSecureBuffer(capacity int) *SecureBuffer {
	sb := &SecureBuffer{
		data:      make([]byte, 0, capacity),
		closed:    false,
		finalizer: true,
	}

	// Set finalizer to catch forgotten Close() calls
	runtime.SetFinalizer(sb, func(s *SecureBuffer) {
		if s.finalizer {
			s.Close()
		}
	})

	return sb
}

// NewSecureBufferFromBytes creates a secure buffer from existing bytes.
// The original bytes are NOT zeroed - caller is responsible for that.
func NewSecureBufferFromBytes(data []byte) *SecureBuffer {
	sb := &SecureBuffer{
		data:      make([]byte, len(data)),
		closed:    false,
		finalizer: true,
	}
	copy(sb.data, data)

	runtime.SetFinalizer(sb, func(s *SecureBuffer) {
		if s.finalizer {
			s.Close()
		}
	})

	return sb
}

// Write appends data to the buffer.
func (sb *SecureBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return 0, ErrInvalidData
	}

	sb.data = append(sb.data, p...)
	return len(p), nil
}

// Bytes returns the buffer contents. Do not store the reference.
func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return nil
	}
	return sb.data
}

// Len returns the length of the buffer.
func (sb *SecureBuffer) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.data)
}

// Close securely clears the buffer contents and marks it as closed.
func (sb *SecureBuffer) Close() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return nil
	}

	// Securely zero the memory
	SecureZero(sb.data)

	// Clear the slice header
	sb.data = nil
	sb.closed = true
	sb.finalizer = false

	return nil
}

// SecureZero overwrites a byte slice with zeros.
// This is designed to prevent compiler optimizations from removing the zeroing.
//
// Note: Go's GC may have already copied data, so this is defense-in-depth.
// For truly sensitive data, consider using locked memory (mlock) via CGo.
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}

	// Use volatile-like semantics to prevent optimization
	// The pointer cast prevents the compiler from optimizing away the zeroing
	ptr := unsafe.Pointer(&b[0])
	for i := range b {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))) = 0
	}

	// Memory barrier to ensure writes are not reordered
	runtime.KeepAlive(b)
}

// SecureZeroString securely zeros a string's underlying bytes.
// WARNING: Strings in Go are immutable, this violates that invariant.
// Only use this on strings that you own and will not use again.
func SecureZeroString(s *string) {
	if s == nil || *s == "" {
		return
	}

	// Get the string header to access underlying bytes
	// This is unsafe and violates Go's string immutability
	sh := (*struct {
		data unsafe.Pointer
		len  int
	})(unsafe.Pointer(s))

	if sh.data == nil || sh.len == 0 {
		return
	}

	// Zero the underlying bytes
	b := unsafe.Slice((*byte)(sh.data), sh.len)
	SecureZero(b)

	// Clear the string reference
	*s = ""
}

// SecureSession holds decrypted credentials for a limited time.
// Automatically clears credentials after timeout.
type SecureSession struct {
	credentials *SecureBuffer
	expiresAt   time.Time
	mu          sync.RWMutex
	closed      bool
	onExpire    func()
}

// NewSecureSession creates a new session that expires after the given duration.
// The onExpire callback is called when the session expires (can be nil).
func NewSecureSession(timeout time.Duration, onExpire func()) *SecureSession {
	ss := &SecureSession{
		credentials: nil,
		expiresAt:   time.Now().Add(timeout),
		closed:      false,
		onExpire:    onExpire,
	}

	// Start expiration timer
	go func() {
		time.Sleep(timeout)
		ss.Expire()
	}()

	return ss
}

// SetCredentials stores encrypted credentials in the session.
// Previous credentials are securely cleared.
func (ss *SecureSession) SetCredentials(creds []byte) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.closed {
		return
	}

	// Clear previous credentials
	if ss.credentials != nil {
		ss.credentials.Close()
	}

	ss.credentials = NewSecureBufferFromBytes(creds)
	ss.expiresAt = time.Now().Add(30 * time.Minute) // Reset timeout
}

// GetCredentials returns the credentials if session is valid.
// Returns nil if session has expired or has no credentials.
func (ss *SecureSession) GetCredentials() []byte {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.closed || ss.credentials == nil {
		return nil
	}

	if time.Now().After(ss.expiresAt) {
		return nil
	}

	return ss.credentials.Bytes()
}

// IsValid returns true if the session is still valid.
func (ss *SecureSession) IsValid() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	return !ss.closed && time.Now().Before(ss.expiresAt)
}

// TimeRemaining returns the time until session expires.
func (ss *SecureSession) TimeRemaining() time.Duration {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.closed {
		return 0
	}

	remaining := time.Until(ss.expiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Refresh extends the session timeout.
func (ss *SecureSession) Refresh(timeout time.Duration) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.closed {
		return
	}

	ss.expiresAt = time.Now().Add(timeout)
}

// Expire immediately expires the session and clears credentials.
func (ss *SecureSession) Expire() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.closed {
		return
	}

	if ss.credentials != nil {
		ss.credentials.Close()
		ss.credentials = nil
	}

	ss.closed = true

	if ss.onExpire != nil {
		go ss.onExpire()
	}
}

// Close is an alias for Expire.
func (ss *SecureSession) Close() error {
	ss.Expire()
	return nil
}

// SessionManager manages multiple user sessions.
type SessionManager struct {
	sessions map[int64]*SecureSession // telegram_id -> session
	mu       sync.RWMutex
	timeout  time.Duration
}

// NewSessionManager creates a new session manager with the given default timeout.
func NewSessionManager(defaultTimeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[int64]*SecureSession),
		timeout:  defaultTimeout,
	}

	// Start cleanup goroutine
	go sm.cleanupLoop()

	return sm
}

// GetSession returns the session for a user, or nil if not found/expired.
func (sm *SessionManager) GetSession(userID int64) *SecureSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[userID]
	if !exists || !session.IsValid() {
		return nil
	}
	return session
}

// CreateSession creates a new session for a user.
// Any existing session for that user is expired first.
func (sm *SessionManager) CreateSession(userID int64) *SecureSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Expire existing session
	if existing, exists := sm.sessions[userID]; exists {
		existing.Expire()
	}

	session := NewSecureSession(sm.timeout, func() {
		sm.removeSession(userID)
	})

	sm.sessions[userID] = session
	return session
}

// ExpireSession expires a user's session.
func (sm *SessionManager) ExpireSession(userID int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[userID]; exists {
		session.Expire()
		delete(sm.sessions, userID)
	}
}

// removeSession removes a session from the map (called by session expiry).
func (sm *SessionManager) removeSession(userID int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, userID)
}

// cleanupLoop periodically removes expired sessions.
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		for userID, session := range sm.sessions {
			if !session.IsValid() {
				session.Expire()
				delete(sm.sessions, userID)
			}
		}
		sm.mu.Unlock()
	}
}

// ActiveSessions returns the number of active sessions.
func (sm *SessionManager) ActiveSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, session := range sm.sessions {
		if session.IsValid() {
			count++
		}
	}
	return count
}
