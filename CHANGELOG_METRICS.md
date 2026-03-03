# Changelog Entry: Prometheus Metrics for Remote Node Health

## [Unreleased]

### Added

#### Prometheus Metrics Export
- **Remote Node Health Monitoring**: Added comprehensive Prometheus metrics for monitoring remote Stellar node health and enabling staleness alerting
  - `remote_node_last_response_timestamp_seconds`: Gauge tracking Unix timestamp of last successful response per node (enables staleness detection)
  - `remote_node_response_total`: Counter tracking total responses by status (success/error) per node
  - `remote_node_response_duration_seconds`: Histogram measuring request duration per node
  - `simulation_execution_total`: Counter tracking total simulation executions by status
  
- **Metrics Endpoint**: Daemon server now exposes `/metrics` endpoint at `http://localhost:8080/metrics` for Prometheus scraping

- **Automatic Metric Recording**: Metrics are automatically recorded for:
  - Horizon API calls (`GetTransaction`)
  - Soroban RPC calls (`GetLedgerEntries`)
  - All simulation executions
  
- **Per-Node Tracking**: All remote node metrics are labeled by `node_address` and `network` for granular monitoring

#### Documentation
- `docs/PROMETHEUS_METRICS.md`: Comprehensive guide with metric descriptions, PromQL queries, alerting rules, and Grafana dashboard examples
- `docs/METRICS_VERIFICATION.md`: Step-by-step manual verification guide with automated verification script
- `docs/METRICS_QUICK_REFERENCE.md`: Quick reference card for DevOps engineers
- `internal/metrics/README.md`: Package documentation with usage examples

#### Testing
- Unit tests for all metric recording functions
- Integration tests for HTTP metrics endpoint and staleness detection
- Manual verification procedures and scripts

### Changed
- **Daemon Server**: Added Prometheus metrics endpoint handler
- **Simulator Runner**: Now records simulation execution metrics with success/failure tracking
- **RPC Client**: Now records remote node response metrics including timestamp, status, and duration

### Dependencies
- Added `github.com/prometheus/client_golang v1.20.5` for Prometheus client library

## Usage Example

### Start Daemon with Metrics
```bash
erst daemon --port 8080 --network testnet
```

### Access Metrics
```bash
curl http://localhost:8080/metrics
```

### Example Alert (Staleness Detection)
```yaml
alert: RemoteNodeStale
expr: time() - remote_node_last_response_timestamp_seconds > 60
for: 1m
labels:
  severity: warning
annotations:
  summary: "Remote node {{ $labels.node_address }} is stale"
  description: "Node hasn't responded in {{ $value }} seconds"
```

## Migration Notes

No breaking changes. Metrics are automatically enabled when running the daemon. No configuration required.

To integrate with Prometheus, add the daemon as a scrape target:

```yaml
scrape_configs:
  - job_name: 'erst-daemon'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

## Benefits

1. **Proactive Monitoring**: Detect node staleness before it impacts operations
2. **Performance Tracking**: Monitor response times and identify degradation
3. **Error Detection**: Track error rates and patterns per node
4. **Network Visibility**: Separate metrics by Stellar network (testnet/mainnet/futurenet)
5. **Standard Integration**: Works with standard Prometheus/Grafana stack

## Related Issues

Closes: #[issue-number] - Add Prometheus metrics for remote node health monitoring
