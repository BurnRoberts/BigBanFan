package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents the severity of a log entry.
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

// logRingBuf is a fixed-capacity ring buffer for the most recent log lines.
// Separate from the main logger mutex so log reads never contend with writes.
type logRingBuf struct {
	mu    sync.Mutex
	lines [logBufCap]string
	head  int // index of oldest entry (write cursor)
	count int // number of valid entries (≤ logBufCap)
}

const logBufCap = 100

func (r *logRingBuf) append(line string) {
	r.mu.Lock()
	r.lines[r.head] = line
	r.head = (r.head + 1) % logBufCap
	if r.count < logBufCap {
		r.count++
	}
	r.mu.Unlock()
}

// snapshot returns all buffered lines in chronological order (oldest first).
func (r *logRingBuf) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil
	}
	out := make([]string, r.count)
	oldest := (r.head - r.count + logBufCap) % logBufCap
	for i := 0; i < r.count; i++ {
		out[i] = r.lines[(oldest+i)%logBufCap]
	}
	return out
}

// ringBuf is the package-level ring buffer for the most recent log lines.
var ringBuf logRingBuf

// GetRecentLines returns up to the last 100 log lines in chronological order.
// Thread-safe. Returns nil if the buffer is empty.
func GetRecentLines() []string {
	return ringBuf.snapshot()
}

// Logger writes timestamped, leveled log entries to a file (and optionally stderr).
//
// Init is NOT thread-safe and must be called once at startup before any
// logging calls are made. After Init, all logging methods are fully thread-safe.
type Logger struct {
	mu       sync.Mutex
	minLevel Level
	out      io.Writer
	file     *os.File // non-nil when logging to a file; used by Reopen
	filePath string   // stored for Reopen
}

var std *Logger

// Init initialises the package-level logger.
// logPath may be "" to log only to stderr.
// Init is NOT thread-safe; call it exactly once at daemon startup.
func Init(logPath string, levelStr string) error {
	var writers []io.Writer
	writers = append(writers, os.Stderr)

	var f *os.File
	if logPath != "" {
		var err error
		f, err = os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("logger: open %s: %w", logPath, err)
		}
		writers = append(writers, f)
	}

	std = &Logger{
		minLevel: parseLevel(levelStr),
		out:      io.MultiWriter(writers...),
		file:     f,
		filePath: logPath,
	}
	return nil
}

// Reopen closes and re-opens the log file, then replaces the writer.
// Call this from a SIGHUP handler to support logrotate without restarting
// the daemon. Safe to call from a signal goroutine.
// No-op if the logger was initialised without a file path.
func Reopen() error {
	if std == nil || std.filePath == "" {
		return nil
	}
	f, err := os.OpenFile(std.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("logger: reopen %s: %w", std.filePath, err)
	}
	std.mu.Lock()
	old := std.file
	std.file = f
	std.out = io.MultiWriter(os.Stderr, f)
	std.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

func parseLevel(s string) Level {
	switch s {
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func levelStr(l Level) string {
	switch l {
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// LineFunc is a callback invoked for every log line that passes the min-level filter.
// level is "info", "warn", or "error". line is the full formatted log string (without trailing newline).
type LineFunc func(level, line string)

// subMu guards the subscriber slot.
var subMu sync.RWMutex
var subscriber LineFunc

// SetSubscriber registers a callback to receive all log lines.
// Only one subscriber is supported at a time; calling again replaces the previous one.
func SetSubscriber(fn LineFunc) {
	subMu.Lock()
	subscriber = fn
	subMu.Unlock()
}

// ClearSubscriber removes the current subscriber.
func ClearSubscriber() {
	subMu.Lock()
	subscriber = nil
	subMu.Unlock()
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.minLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("2006-01-02T15:04:05Z07:00")
	line := fmt.Sprintf("%s [%s] %s", ts, levelStr(level), msg)
	l.mu.Lock()
	_, _ = l.out.Write([]byte(line + "\n"))
	l.mu.Unlock()

	// Append to ring buffer so management clients can fetch recent history.
	ringBuf.append(line)

	// Forward to subscriber (e.g. management session log stream) outside the logger lock.
	subMu.RLock()
	fn := subscriber
	subMu.RUnlock()
	if fn != nil {
		lstr := "info"
		switch level {
		case LevelWarn:
			lstr = "warn"
		case LevelError:
			lstr = "error"
		}
		fn(lstr, line)
	}
}

// Info logs an informational message.
func Info(format string, args ...interface{}) {
	if std != nil {
		std.log(LevelInfo, format, args...)
	}
}

// Warn logs a warning message.
func Warn(format string, args ...interface{}) {
	if std != nil {
		std.log(LevelWarn, format, args...)
	}
}

// Error logs an error message.
func Error(format string, args ...interface{}) {
	if std != nil {
		std.log(LevelError, format, args...)
	}
}
