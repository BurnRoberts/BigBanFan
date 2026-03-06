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

// Logger writes timestamped, leveled log entries to a file (and optionally stderr).
type Logger struct {
	mu       sync.Mutex
	minLevel Level
	out      io.Writer
}

var std *Logger

// Init initialises the package-level logger.
// logPath may be "" to log only to stderr.
func Init(logPath string, levelStr string) error {
	var writers []io.Writer
	writers = append(writers, os.Stderr)

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("logger: open %s: %w", logPath, err)
		}
		writers = append(writers, f)
	}

	std = &Logger{
		minLevel: parseLevel(levelStr),
		out:      io.MultiWriter(writers...),
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
		return "WARN "
	case LevelError:
		return "ERROR"
	default:
		return "INFO "
	}
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.minLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("2006-01-02T15:04:05Z07:00")
	line := fmt.Sprintf("%s [%s] %s\n", ts, levelStr(level), msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write([]byte(line))
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
