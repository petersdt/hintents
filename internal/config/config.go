// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dotandev/hintents/internal/errors"
)

type Parser interface {
	Parse(*Config) error
}

type DefaultAssigner interface {
	Apply(*Config)
}

type Validator interface {
	Validate(*Config) error
}

type CompositeValidator struct {
	validators []Validator
}

func NewCompositeValidator(validators ...Validator) CompositeValidator {
	return CompositeValidator{validators: validators}
}

func (v CompositeValidator) Validate(cfg *Config) error {
	for _, validator := range v.validators {
		if err := validator.Validate(cfg); err != nil {
			return err
		}
	}
	return nil
}

type RequiredFieldsValidator struct{}

func (RequiredFieldsValidator) Validate(cfg *Config) error {
	if cfg.RpcUrl == "" {
		return errors.WrapValidationError("rpc_url cannot be empty")
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

type RequestTimeoutValidator struct{}

const maxRequestTimeout = 300

func (RequestTimeoutValidator) Validate(cfg *Config) error {
	if cfg.RequestTimeout == 0 {
		return nil
	}
	if cfg.RequestTimeout < 1 || cfg.RequestTimeout > maxRequestTimeout {
		return errors.WrapValidationError(fmt.Sprintf("request_timeout must be between 1 and %d", maxRequestTimeout))
	}
	return nil
}

type ConfigDefaultsAssigner struct{}

func (ConfigDefaultsAssigner) Apply(cfg *Config) {
	if cfg.RpcUrl == "" {
		cfg.RpcUrl = defaultConfig.RpcUrl
	}
	if cfg.Network == "" {
		cfg.Network = defaultConfig.Network
	}
	if cfg.SimulatorPath == "" {
		cfg.SimulatorPath = defaultConfig.SimulatorPath
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultConfig.LogLevel
	}
	if cfg.CachePath == "" {
		cfg.CachePath = defaultConfig.CachePath
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
}

type EnvParser struct{}

func (EnvParser) Parse(cfg *Config) error {
	if v := os.Getenv("ERST_RPC_URL"); v != "" {
		cfg.RpcUrl = v
	}
	if v := os.Getenv("ERST_NETWORK"); v != "" {
		cfg.Network = Network(v)
	}
	if v := os.Getenv("ERST_SIMULATOR_PATH"); v != "" {
		cfg.SimulatorPath = v
	}
	if v := os.Getenv("ERST_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("ERST_CACHE_PATH"); v != "" {
		cfg.CachePath = v
	}
	if v := os.Getenv("ERST_RPC_TOKEN"); v != "" {
		cfg.RPCToken = v
	}
	if v := os.Getenv("ERST_CRASH_ENDPOINT"); v != "" {
		cfg.CrashEndpoint = v
	}
	if v := os.Getenv("ERST_SENTRY_DSN"); v != "" {
		cfg.CrashSentryDSN = v
	}

	if v := os.Getenv("ERST_REQUEST_TIMEOUT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return errors.WrapValidationError("ERST_REQUEST_TIMEOUT must be an integer")
		}
		cfg.RequestTimeout = n
	}

	switch strings.ToLower(os.Getenv("ERST_CRASH_REPORTING")) {
	case "":
	case "1", "true", "yes":
		cfg.CrashReporting = true
	case "0", "false", "no":
		cfg.CrashReporting = false
	default:
		return errors.WrapValidationError("ERST_CRASH_REPORTING must be a boolean")
	}

	if urlsEnv := os.Getenv("ERST_RPC_URLS"); urlsEnv != "" {
		cfg.RpcUrls = strings.Split(urlsEnv, ",")
		for i := range cfg.RpcUrls {
			cfg.RpcUrls[i] = strings.TrimSpace(cfg.RpcUrls[i])
		}
	} else if urlsEnv := os.Getenv("STELLAR_RPC_URLS"); urlsEnv != "" {
		cfg.RpcUrls = strings.Split(urlsEnv, ",")
		for i := range cfg.RpcUrls {
			cfg.RpcUrls[i] = strings.TrimSpace(cfg.RpcUrls[i])
		}
	}

	return nil
}

type Network string

const (
	NetworkPublic     Network = "public"
	NetworkTestnet    Network = "testnet"
	NetworkFuturenet  Network = "futurenet"
	NetworkStandalone Network = "standalone"
)

var validNetworks = map[string]bool{
	string(NetworkPublic):     true,
	string(NetworkTestnet):    true,
	string(NetworkFuturenet):  true,
	string(NetworkStandalone): true,
}

type Config struct {
	RpcUrl            string   `json:"rpc_url,omitempty"`
	RpcUrls           []string `json:"rpc_urls,omitempty"`
	Network           Network  `json:"network,omitempty"`
	NetworkPassphrase string   `json:"network_passphrase,omitempty"`
	SimulatorPath     string   `json:"simulator_path,omitempty"`
	LogLevel          string   `json:"log_level,omitempty"`
	CachePath         string   `json:"cache_path,omitempty"`
	RPCToken          string   `json:"rpc_token,omitempty"`
	CrashReporting    bool     `json:"crash_reporting,omitempty"`
	CrashEndpoint     string   `json:"crash_endpoint,omitempty"`
	CrashSentryDSN    string   `json:"crash_sentry_dsn,omitempty"`
	RequestTimeout    int      `json:"request_timeout,omitempty"`
}

func GetGeneralConfigPath() (string, error) {
	configDir, err := GetConfigPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.json"), nil
}

func LoadConfig() (*Config, error) {
	configPath, err := GetGeneralConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, errors.WrapConfigError("failed to read config file", err)
	}

	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, errors.WrapConfigError("failed to parse config file", err)
	}

	return config, nil
}

// Load loads the configuration from environment variables and TOML files.
// The lifecycle follows three distinct phases: load, merge defaults, validate.
func Load() (*Config, error) {
	cfg := &Config{}
	parsers := []Parser{EnvParser{}, fileParser{}}
	for _, parser := range parsers {
		if err := parser.Parse(cfg); err != nil {
			return nil, err
		}
	}

	ConfigDefaultsAssigner{}.Apply(cfg)

	// Phase 2: Merge defaults for any fields still unset.
	cfg.MergeDefaults()

	// Phase 3: Validate.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

type fileParser struct{}

func (fileParser) Parse(cfg *Config) error {
	return cfg.loadFromFile()
}

func (c *Config) loadFromFile() error {
	paths := []string{
		".erst.toml",
		filepath.Join(os.ExpandEnv("$HOME"), ".erst.toml"),
		"/etc/erst/config.toml",
	}

	for _, path := range paths {
		if err := c.loadTOML(path); err == nil {
			return nil
		}
	}

	return nil
}

func (c *Config) loadTOML(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return c.parseTOML(string(data))
}

func (c *Config) parseTOML(content string) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		rawVal := strings.TrimSpace(parts[1])

		if key == "rpc_urls" && strings.HasPrefix(rawVal, "[") && strings.HasSuffix(rawVal, "]") {
			// Basic array parsing for TOML-like lists: ["a", "b"]
			rawVal = strings.Trim(rawVal, "[]")
			parts := strings.Split(rawVal, ",")
			var urls []string
			for _, p := range parts {
				urls = append(urls, strings.Trim(strings.TrimSpace(p), "\"'"))
			}
			c.RpcUrls = urls
			continue
		}

		value := strings.Trim(rawVal, "\"'")

		switch key {
		case "rpc_url":
			c.RpcUrl = value
		case "rpc_urls":
			// Fallback if not an array but comma-separated string
			c.RpcUrls = strings.Split(value, ",")
			for i := range c.RpcUrls {
				c.RpcUrls[i] = strings.TrimSpace(c.RpcUrls[i])
			}
		case "network":
			c.Network = Network(value)
		case "network_passphrase":
			c.NetworkPassphrase = value
		case "simulator_path":
			c.SimulatorPath = value
		case "log_level":
			c.LogLevel = value
		case "cache_path":
			c.CachePath = value
		case "rpc_token":
			c.RPCToken = value
		case "crash_reporting":
			switch strings.ToLower(value) {
			case "true", "1", "yes":
				c.CrashReporting = true
			case "false", "0", "no":
				c.CrashReporting = false
			default:
				return errors.WrapValidationError("crash_reporting must be a boolean")
			}
		case "crash_endpoint":
			c.CrashEndpoint = value
		case "crash_sentry_dsn":
			c.CrashSentryDSN = value
		case "request_timeout":
			n, err := strconv.Atoi(value)
			if err != nil {
				return errors.WrapValidationError("request_timeout must be an integer")
			}
			c.RequestTimeout = n
		}
	}

	return nil
}

// SaveConfig saves the configuration to disk (JSON format)
func SaveConfig(config *Config) error {
	configPath, err := GetGeneralConfigPath()
	if err != nil {
		return err
	}

	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return errors.WrapConfigError("failed to create config directory", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.WrapConfigError("failed to marshal config", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return errors.WrapConfigError("failed to write config file", err)
	}

	return nil
}

func (c *Config) Validate() error {
	validator := NewCompositeValidator(
		RequiredFieldsValidator{},
		NetworkValidator{},
		RequestTimeoutValidator{},
	)
	return validator.Validate(c)
}

func (c *Config) NetworkURL() string {
	switch c.Network {
	case NetworkPublic:
		return "https://soroban.stellar.org"
	case NetworkTestnet:
		return "https://soroban-testnet.stellar.org"
	case NetworkFuturenet:
		return "https://soroban-futurenet.stellar.org"
	case NetworkStandalone:
		return "http://localhost:8000"
	default:
		return c.RpcUrl
	}
}

func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{RPC: %s, Network: %s, LogLevel: %s, CachePath: %s}",
		c.RpcUrl, c.Network, c.LogLevel, c.CachePath,
	)
}

func DefaultConfig() *Config {
	return &Config{
		RpcUrl:         defaultConfig.RpcUrl,
		Network:        defaultConfig.Network,
		SimulatorPath:  defaultConfig.SimulatorPath,
		LogLevel:       defaultConfig.LogLevel,
		CachePath:      defaultConfig.CachePath,
		RequestTimeout: defaultConfig.RequestTimeout,
	}
}

func NewConfig(rpcUrl string, network Network) *Config {
	return &Config{
		RpcUrl:         rpcUrl,
		Network:        network,
		SimulatorPath:  defaultConfig.SimulatorPath,
		LogLevel:       defaultConfig.LogLevel,
		CachePath:      defaultConfig.CachePath,
		RequestTimeout: defaultConfig.RequestTimeout,
	}
}

func (c *Config) WithSimulatorPath(path string) *Config {
	c.SimulatorPath = path
	return c
}

func (c *Config) WithLogLevel(level string) *Config {
	c.LogLevel = level
	return c
}

func (c *Config) WithCachePath(path string) *Config {
	c.CachePath = path
	return c
}

func (c *Config) WithRequestTimeout(seconds int) *Config {
	c.RequestTimeout = seconds
	return c
}
