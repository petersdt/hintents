// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	Logger *slog.Logger
	level  = new(slog.LevelVar)
	mu     sync.Mutex
)

func init() {
	lvl := parseLevelFromEnv()
	initLogger(lvl, os.Stderr, false)
}

func parseLevelFromEnv() slog.Level {
	return ParseLogLevel(os.Getenv("ERST_LOG_LEVEL"))
}

// ParseLogLevel converts a human-readable level string (e.g. "debug", "info",
// "warn", "error") into the corresponding slog.Level. Unknown values default
// to slog.LevelInfo.
func ParseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace", "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// RustLogFilter returns the RUST_LOG-compatible filter string that corresponds
// to the given ERST log level name. This is used when spawning the Rust
// simulator subprocess so that a single ERST_LOG_LEVEL value controls both the
// Go logger and the Rust tracing subscriber.
func RustLogFilter(erstLevel string) string {
	switch strings.ToLower(strings.TrimSpace(erstLevel)) {
	case "trace":
		return "trace"
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error":
		return "error"
	default:
		return "info"
	}
}

func initLogger(lvl slog.Level, w io.Writer, useJSON bool) {
	if w == nil {
		w = os.Stderr
	}

	level.Set(lvl)

	var handler slog.Handler
	if useJSON {
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:     level,
			AddSource: true,
		})
	} else {
		handler = NewTextHandler(w, &slog.HandlerOptions{
			Level:     level,
			AddSource: true,
		})
	}

	Logger = slog.New(handler)
}

func SetLevel(lvl slog.Level) {
	mu.Lock()
	defer mu.Unlock()
	level.Set(lvl)
}

func SetOutput(w io.Writer, useJSON bool) {
	mu.Lock()
	defer mu.Unlock()
	initLogger(level.Level(), w, useJSON)
}

type TextHandler struct {
	handler slog.Handler
}

func NewTextHandler(w io.Writer, opts *slog.HandlerOptions) *TextHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &TextHandler{
		handler: slog.NewTextHandler(w, opts),
	}
}

func (h *TextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *TextHandler) Handle(ctx context.Context, record slog.Record) error {
	return h.handler.Handle(ctx, record)
}

func (h *TextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TextHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *TextHandler) WithGroup(name string) slog.Handler {
	return &TextHandler{handler: h.handler.WithGroup(name)}
}
