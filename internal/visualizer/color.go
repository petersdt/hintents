// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package visualizer

import (
	"os"

	"github.com/mattn/go-isatty"
)

// ANSI SGR (Select Graphic Rendition) escape codes for terminal colors.
const (
	sgrRed     = "\033[31m"
	sgrGreen   = "\033[32m"
	sgrYellow  = "\033[33m"
	sgrBlue    = "\033[34m"
	sgrMagenta = "\033[35m"
	sgrCyan    = "\033[36m"
	sgrBold    = "\033[1m"
	sgrDim     = "\033[2m"
)

var defaultRenderer terminal.Renderer = terminal.NewANSIRenderer()

// ColorEnabled reports whether ANSI color output should be used.
func ColorEnabled() bool {
	// NO_COLOR must always take precedence.
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isatty.IsTerminal(os.Stdout.Fd())
}

// Colorize returns text with ANSI color if enabled, otherwise plain text.
func Colorize(text string, color string) string {
	if !ColorEnabled() {
		return text
	}

	var code string
	switch color {
	case "red":
		code = sgrRed
	case "green":
		code = sgrGreen
	case "yellow":
		code = sgrYellow
	case "blue":
		code = sgrBlue
	case "magenta":
		code = sgrMagenta
	case "cyan":
		code = sgrCyan
	case "dim":
		code = sgrDim
	case "bold":
		code = sgrBold
	default:
		return text
	}

	return code + text + sgrReset
}

// ContractBoundary returns a visual separator for cross-contract call transitions.
func ContractBoundary(fromContract, toContract string) string {
	line := "--- contract boundary: " + fromContract + " -> " + toContract + " ---"
	if !ColorEnabled() {
		return line
	}
	return sgrMagenta + sgrBold + line + sgrReset
}

// ContractBoundary returns a visual separator for cross-contract call transitions.
func ContractBoundary(fromContract, toContract string) string {
	if ColorEnabled() {
		return sgrMagenta + sgrBold + "--- contract boundary: " + fromContract + " -> " + toContract + " ---" + sgrReset
	}
	return "--- contract boundary: " + fromContract + " -> " + toContract + " ---"
}

// Success returns a success indicator.
func Success() string {
	return defaultRenderer.Success()
}

// Warning returns a warning indicator.
func Warning() string {
	return defaultRenderer.Warning()
}

// Error returns an error indicator.
func Error() string {
	return defaultRenderer.Error()
}

// Info returns an info indicator.
func Info() string {
	return Colorize("[i]", "cyan")
}

// ContractBoundary returns a visual separator indicating a cross-contract
// transition from fromContract to toContract.
func ContractBoundary(fromContract, toContract string) string {
	text := "--- contract boundary: " + fromContract + " -> " + toContract + " ---"
	return Colorize(text, sgrMagenta+sgrBold)
}

// Symbol returns a symbol name rendered as ASCII markers.
//
//nolint:gocyclo
func Symbol(name string) string {
	if ColorEnabled() {
		switch name {
		case "check":
			return "[OK]"
		case "cross":
			return "[FAIL]"
		case "warn":
			return "[!]"
		case "arrow_r":
			return "->"
		case "arrow_l":
			return "<-"
		case "target":
			return "[TARGET]"
		case "pin":
			return "*"
		case "wrench":
			return "[TOOL]"
		case "chart":
			return "[STATS]"
		case "list":
			return "[LIST]"
		case "play":
			return "[PLAY]"
		case "book":
			return "[DOC]"
		case "wave":
			return "[HELLO]"
		case "magnify":
			return "[SEARCH]"
		case "logs":
			return "[LOGS]"
		case "events":
			return "[NET]"
		default:
			return name
		}
	}

	switch name {
	case "check":
		return "[OK]"
	case "cross":
		return "[X]"
	case "warn":
		return "[!]"
	case "arrow_r":
		return "->"
	case "arrow_l":
		return "<-"
	case "target":
		return ">>"
	case "pin":
		return "*"
	case "wrench":
		return "[*]"
	case "chart":
		return "[#]"
	case "list":
		return "[.]"
	case "play":
		return ">"
	case "book":
		return "[?]"
	case "wave":
		return ""
	case "magnify":
		return "[?]"
	case "logs":
		return "[Logs]"
	case "events":
		return "[Events]"
	default:
		return name
	}
}
