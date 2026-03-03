// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"

	"github.com/dotandev/hintents/internal/errors"
)

type Validator interface {
	Validate(cfg *Config) error
}

var defaultValidators = []Validator{
	RPCValidator{},
	NetworkValidator{},
	LogLevelValidator{},
	TimeoutValidator{},
	CrashReportingValidator{},
}

type RPCValidator struct{}

func (RPCValidator) Validate(cfg *Config) error {
	if cfg.RpcUrl == "" {
		return errors.WrapValidationError("rpc_url cannot be empty")
	}
	if !strings.HasPrefix(cfg.RpcUrl, "http://") && !strings.HasPrefix(cfg.RpcUrl, "https://") {
		return errors.WrapValidationError(fmt.Sprintf("rpc_url must use http or https scheme, got %q", cfg.RpcUrl))
	}
	return nil
}

type NetworkValidator struct{}

func (NetworkValidator) Validate(cfg *Config) error {
	if cfg.Network != "" && !validNetworks[string(cfg.Network)] {
		return errors.WrapInvalidNetwork(string(cfg.Network))
	}
	return nil
}

var validLogLevels = map[string]bool{
	"trace": true,
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

type LogLevelValidator struct{}

func (LogLevelValidator) Validate(cfg *Config) error {
	if cfg.LogLevel != "" && !validLogLevels[cfg.LogLevel] {
		return errors.WrapValidationError(
			fmt.Sprintf("log_level must be one of trace, debug, info, warn, error; got %q", cfg.LogLevel),
		)
	}
	return nil
}

const maxRequestTimeout = 300

type TimeoutValidator struct{}

func (TimeoutValidator) Validate(cfg *Config) error {
	if cfg.RequestTimeout <= 0 {
		return errors.WrapValidationError("request_timeout must be greater than 0")
	}
	if cfg.RequestTimeout > maxRequestTimeout {
		return errors.WrapValidationError(
			fmt.Sprintf("request_timeout must be at most %d seconds, got %d", maxRequestTimeout, cfg.RequestTimeout),
		)
	}
	return nil
}

type CrashReportingValidator struct{}

func (CrashReportingValidator) Validate(cfg *Config) error {
	if !cfg.CrashReporting {
		return nil
	}
	if cfg.CrashEndpoint == "" && cfg.CrashSentryDSN == "" {
		return errors.WrapValidationError(
			"crash_reporting is enabled but neither crash_endpoint nor crash_sentry_dsn is set",
		)
	}
	if cfg.CrashSentryDSN != "" && !strings.HasPrefix(cfg.CrashSentryDSN, "https://") {
		return errors.WrapValidationError(
			fmt.Sprintf("crash_sentry_dsn must use https scheme, got %q", cfg.CrashSentryDSN),
		)
	}
	return nil
}

func runValidators(cfg *Config, validators []Validator) error {
	for _, v := range validators {
		if err := v.Validate(cfg); err != nil {
			return err
		}
	}
	return nil
}
