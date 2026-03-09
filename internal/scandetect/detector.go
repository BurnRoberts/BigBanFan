// Package scandetect tracks inbound connection failures per source IP using a
// sliding time window. When a source IP accumulates failures >= threshold within
// the window duration, the registered OnBan callback is fired.
//
// Intended use: inbound TLS probes / port scanners that connect but fail to
// complete a valid BigBanFan handshake.
package scandetect

import (
	"bigbanfan/internal/logger"
	"net"
	"sync"
	"time"
)

// Detector is a thread-safe sliding-window failure tracker.
type Detector struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	hits      map[string][]time.Time // source IP → timestamps of failures
	onBan     func(string)
	stopCh    chan struct{}
	stopOnce  sync.Once // guards against double-close of stopCh
}

// New creates a Detector. window is the sliding time window; threshold is the
// number of failures within that window before onBan(ip) is called.
func New(threshold int, window time.Duration, onBan func(string)) *Detector {
	d := &Detector{
		window:    window,
		threshold: threshold,
		hits:      make(map[string][]time.Time),
		onBan:     onBan,
		stopCh:    make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

// RecordFailure records one failed inbound connection attempt from the given
// remote address (host:port or bare IP). If the source has reached the
// threshold within the sliding window, onBan is called with the bare IP.
func (d *Detector) RecordFailure(remote string) {
	ip := bareIP(remote)
	if ip == "" {
		return
	}

	now := time.Now()

	d.mu.Lock()
	// Append and prune stale entries for this IP.
	times := append(d.hits[ip], now)
	cutoff := now.Add(-d.window)
	start := 0
	for start < len(times) && times[start].Before(cutoff) {
		start++
	}
	times = times[start:]
	d.hits[ip] = times
	count := len(times)
	d.mu.Unlock()

	logger.Info("scan-detect: %s failure count=%d/%d (window=%s)", ip, count, d.threshold, d.window)

	if count >= d.threshold {
		logger.Warn("scan-detect: THRESHOLD REACHED for %s (%d failures in %s) — auto-banning", ip, count, d.window)
		// Delete and fire under lock so two simultaneous connections at the
		// threshold can't both call onBan for the same IP.
		d.mu.Lock()
		// Re-check: another goroutine may have already fired and deleted.
		if _, still := d.hits[ip]; still {
			delete(d.hits, ip)
			d.mu.Unlock()
			if d.onBan != nil {
				d.onBan(ip)
			}
		} else {
			d.mu.Unlock()
		}
	}
}

// Stop shuts down the background cleanup goroutine.
// Safe to call more than once — only the first call closes the channel.
func (d *Detector) Stop() {
	d.stopOnce.Do(func() { close(d.stopCh) })
}

// cleanupLoop periodically evicts source IPs whose last failure is older than
// the window, to prevent unbounded memory growth.
func (d *Detector) cleanupLoop() {
	ticker := time.NewTicker(d.window)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			cutoff := now.Add(-d.window)
			d.mu.Lock()
			for ip, times := range d.hits {
				// Remove entries older than the window.
				start := 0
				for start < len(times) && times[start].Before(cutoff) {
					start++
				}
				if start == len(times) {
					delete(d.hits, ip)
				} else {
					d.hits[ip] = times[start:]
				}
			}
			d.mu.Unlock()
		}
	}
}

// bareIP extracts the host portion from a host:port string, or returns the
// input unchanged if it has no port. Returns "" if parsing fails.
func bareIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		// Might already be a bare IP.
		if net.ParseIP(remote) != nil {
			return remote
		}
		return ""
	}
	return host
}
