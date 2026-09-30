// Package logging is a thin slog wrapper with optional lumberjack file rotation.
package logging

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Rotation limits are package vars so tests can use a 1MB max without
// writing 100MB. lumberjack measures MaxSize in megabytes (minimum 1).
var (
	maxSizeMB  = 100
	maxBackups = 5
)

// Setup configures slog (and stdlib log output) from logFile and logLevel.
// Empty logFile writes to stdout. Non-empty uses lumberjack at that path.
// The returned cleanup restores previous log destinations and closes the file writer.
func Setup(logFile, logLevel string) (func(), error) {
	level, err := parseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	var (
		writer io.Writer = os.Stdout
		closer io.Closer
	)

	if logFile != "" {
		lj := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    maxSizeMB,
			MaxBackups: maxBackups,
			MaxAge:     0,
			Compress:   false,
		}
		writer = lj
		closer = lj
	}

	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{Level: level})
	prev := slog.Default()

	slog.SetDefault(slog.New(handler))

	prevFlags := log.Flags()
	prevOutput := log.Writer()

	log.SetFlags(0)
	log.SetOutput(writer)

	cleanup := func() {
		slog.SetDefault(prev)
		log.SetFlags(prevFlags)
		log.SetOutput(prevOutput)

		if closer != nil {
			_ = closer.Close()
		}
	}

	return cleanup, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return slog.LevelError, nil
	case "warn":
		return slog.LevelWarn, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want error, warn, info, or debug)", s)
	}
}

// Error logs at error level through the logger configured by Setup.
func Error(msg string, args ...any) { slog.Default().Error(msg, args...) }

// Warn logs at warning level through the logger configured by Setup.
func Warn(msg string, args ...any) { slog.Default().Warn(msg, args...) }

// Info logs at info level through the logger configured by Setup.
func Info(msg string, args ...any) { slog.Default().Info(msg, args...) }

// Debug logs at debug level through the logger configured by Setup.
func Debug(msg string, args ...any) { slog.Default().Debug(msg, args...) }
