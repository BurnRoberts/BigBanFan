package dedupe

import (
	"sync"
	"time"
)

// entry holds a dedupe ID and when it was recorded.
type entry struct {
	seenAt time.Time
}

// Set is a thread-safe in-memory store of dedupe IDs we have already
// processed.  IDs older than ttl are evicted periodically to bound memory.
type Set struct {
	mu       sync.RWMutex
	seen     map[string]entry
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once // guards against double-close of stopCh
}

// New creates a Set that evicts entries older than ttl.
// cleanupInterval controls how often the eviction sweep runs.
func New(ttl, cleanupInterval time.Duration) *Set {
	s := &Set{
		seen:   make(map[string]entry),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go s.cleanupLoop(cleanupInterval)
	return s
}

// MarkSeen records a dedupe ID as seen.
func (s *Set) MarkSeen(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[id] = entry{seenAt: time.Now()}
}

// HasSeen returns true if the dedupe ID has been recorded and has not yet expired.
func (s *Set) HasSeen(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.seen[id]
	if !ok {
		return false
	}
	return time.Since(e.seenAt) < s.ttl
}

// Seed bulk-loads IDs from the persistent store (e.g. on startup from SQLite).
func (s *Set) Seed(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		s.seen[id] = entry{seenAt: time.Now()}
	}
}

// Stop halts the background eviction goroutine.
// Safe to call more than once — only the first call closes the channel.
func (s *Set) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func (s *Set) cleanupLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.evict()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Set) evict() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.seen {
		if now.Sub(e.seenAt) >= s.ttl {
			delete(s.seen, id)
		}
	}
}
