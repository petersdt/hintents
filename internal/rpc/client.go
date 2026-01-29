// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/dotandev/hintents/internal/logger"
	"github.com/dotandev/hintents/internal/telemetry"
	"github.com/stellar/go/clients/horizonclient"
	"go.opentelemetry.io/otel/attribute"
)

// Network types for Stellar
type Network string

const (
	Testnet   Network = "testnet"
	Mainnet   Network = "mainnet"
	Futurenet Network = "futurenet"
)

// Horizon URLs for each network
const (
	TestnetHorizonURL   = "https://horizon-testnet.stellar.org/"
	MainnetHorizonURL   = "https://horizon.stellar.org/"
	FuturenetHorizonURL = "https://horizon-futurenet.stellar.org/"
)

// Soroban RPC URLs
const (
	TestnetSorobanURL   = "https://soroban-testnet.stellar.org"
	MainnetSorobanURL   = "https://mainnet.stellar.validationcloud.io/v1/soroban-rpc-demo" // Public demo endpoint
	FuturenetSorobanURL = "https://rpc-futurenet.stellar.org"
)

// authTransport is a custom HTTP RoundTripper that adds authentication headers
type authTransport struct {
	token     string
	transport http.RoundTripper
}

// RoundTrip implements http.RoundTripper interface
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		// Add Bearer token to Authorization header
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.transport.RoundTrip(req)
}

// Client handles interactions with the Stellar Network
type Client struct {
	Horizon    horizonclient.ClientInterface
	Network    Network
	SorobanURL string
	token      string // stored for reference, not logged
}

// NewClient creates a new RPC client with the specified network
// If network is empty, defaults to Mainnet
// Token can be provided via the token parameter or ERST_RPC_TOKEN environment variable
func NewClient(net Network, token string) *Client {
	if net == "" {
		net = Mainnet
	}

	// Check environment variable if token not provided
	if token == "" {
		token = os.Getenv("ERST_RPC_TOKEN")
	}

	var horizonClient *horizonclient.Client
	var sorobanURL string
	httpClient := createHTTPClient(token)

	switch net {
	case Testnet:
		horizonClient = &horizonclient.Client{
			HorizonURL: TestnetHorizonURL,
			HTTP:       httpClient,
		}
		sorobanURL = TestnetSorobanURL
	case Futurenet:
		horizonClient = &horizonclient.Client{
			HorizonURL: FuturenetHorizonURL,
			HTTP:       httpClient,
		}
		sorobanURL = FuturenetSorobanURL
	case Mainnet:
		fallthrough
	default:
		horizonClient = &horizonclient.Client{
			HorizonURL: MainnetHorizonURL,
			HTTP:       httpClient,
		}
		sorobanURL = MainnetSorobanURL
	}

	if token != "" {
		logger.Logger.Debug("RPC client initialized with authentication")
	} else {
		logger.Logger.Debug("RPC client initialized without authentication")
	}

	return &Client{
		Horizon:    horizonClient,
		Network:    net,
		SorobanURL: sorobanURL,
		token:      token,
	}
}

// NewClientWithURL creates a new RPC client with a custom Horizon URL
// Token can be provided via the token parameter or ERST_RPC_TOKEN environment variable
func NewClientWithURL(url string, net Network, token string) *Client {
	// Check environment variable if token not provided
	if token == "" {
		token = os.Getenv("ERST_RPC_TOKEN")
	}

	// Re-use logic to get default Soroban URL
	defaultClient := NewClient(net, token)

	httpClient := createHTTPClient(token)
	horizonClient := &horizonclient.Client{
		HorizonURL: url,
		HTTP:       httpClient,
	}

	if token != "" {
		logger.Logger.Debug("RPC client initialized with authentication")
	} else {
		logger.Logger.Debug("RPC client initialized without authentication")
	}

	return &Client{
		Horizon:    horizonClient,
		Network:    net,
		SorobanURL: defaultClient.SorobanURL,
		token:      token,
	}
}

// createHTTPClient creates an HTTP client with optional authentication
func createHTTPClient(token string) *http.Client {
	if token == "" {
		return http.DefaultClient
	}

	return &http.Client{
		Transport: &authTransport{
			token:     token,
			transport: http.DefaultTransport,
		},
	}
}

// TransactionResponse contains the raw XDR fields needed for simulation
type TransactionResponse struct {
	EnvelopeXdr   string
	ResultXdr     string
	ResultMetaXdr string
}

// GetTransaction fetches the transaction details and full XDR data
func (c *Client) GetTransaction(ctx context.Context, hash string) (*TransactionResponse, error) {
	tracer := telemetry.GetTracer()
	_, span := tracer.Start(ctx, "rpc_get_transaction")
	span.SetAttributes(
		attribute.String("transaction.hash", hash),
		attribute.String("network", string(c.Network)),
	)
	defer span.End()

	logger.Logger.Debug("Fetching transaction details", "hash", hash)

	tx, err := c.Horizon.TransactionDetail(hash)
	if err != nil {
		span.RecordError(err)
		logger.Logger.Error("Failed to fetch transaction", "hash", hash, "error", err)
		return nil, fmt.Errorf("failed to fetch transaction: %w", err)
	}

	span.SetAttributes(
		attribute.Int("envelope.size_bytes", len(tx.EnvelopeXdr)),
		attribute.Int("result.size_bytes", len(tx.ResultXdr)),
		attribute.Int("result_meta.size_bytes", len(tx.ResultMetaXdr)),
	)

	logger.Logger.Info("Transaction fetched successfully", "hash", hash, "envelope_size", len(tx.EnvelopeXdr))

	return &TransactionResponse{
		EnvelopeXdr:   tx.EnvelopeXdr,
		ResultXdr:     tx.ResultXdr,
		ResultMetaXdr: tx.ResultMetaXdr,
	}, nil
}

type GetLedgerEntriesRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type GetLedgerEntriesResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		Entries []struct {
			Key                string `json:"key"`
			Xdr                string `json:"xdr"`
			LastModifiedLedger int    `json:"lastModifiedLedgerSeq"`
			LiveUntilLedger    int    `json:"liveUntilLedgerSeq"`
		} `json:"entries"`
		LatestLedger int `json:"latestLedger"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// GetLedgerEntries fetches the current state of ledger entries from Soroban RPC
// keys should be a list of base64-encoded XDR LedgerKeys
func (c *Client) GetLedgerEntries(ctx context.Context, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}

	logger.Logger.Debug("Fetching ledger entries", "count", len(keys), "url", c.SorobanURL)

	reqBody := GetLedgerEntriesRequest{
		Jsonrpc: "2.0",
		ID:      1,
		Method:  "getLedgerEntries",
		Params:  []interface{}{keys},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.SorobanURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp GetLedgerEntriesResponse
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error: %s (code %d)", rpcResp.Error.Message, rpcResp.Error.Code)
	}

	entries := make(map[string]string)
	for _, entry := range rpcResp.Result.Entries {
		entries[entry.Key] = entry.Xdr
	}

	logger.Logger.Info("Ledger entries fetched successfully", "found", len(entries), "requested", len(keys))

	return entries, nil
}