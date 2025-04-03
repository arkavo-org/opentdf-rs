# OpenTDF-RS Server Configuration Guide

This document explains the configuration options for the OpenTDF-RS MCP server, including environment variables, performance tuning, and security settings.

## Configuration Methods

The OpenTDF-RS server can be configured using environment variables, which makes it ideal for containerized deployments and CI/CD pipelines.

## Environment Variables

### File Operations

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OPENTDF_MAX_FILE_SIZE` | Maximum allowed file size in bytes | 104857600 (100MB) | `OPENTDF_MAX_FILE_SIZE=52428800` |
| `OPENTDF_SECURE_DELETE_BUFFER` | Buffer size for secure deletion operations | 8192 | `OPENTDF_SECURE_DELETE_BUFFER=16384` |
| `OPENTDF_SECURE_DELETE_PASSES` | Number of overwrite passes for secure deletion | 3 | `OPENTDF_SECURE_DELETE_PASSES=5` |

### Rate Limiting

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OPENTDF_RATE_LIMIT` | Maximum requests per minute | 100 | `OPENTDF_RATE_LIMIT=50` |
| `OPENTDF_BURST_LIMIT` | Maximum burst requests | 20 | `OPENTDF_BURST_LIMIT=10` |

### Metrics and Monitoring

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OPENTDF_ENABLE_METRICS` | Enable Prometheus metrics | true | `OPENTDF_ENABLE_METRICS=false` |
| `OPENTDF_METRICS_PORT` | Port for Prometheus metrics server | 9091 | `OPENTDF_METRICS_PORT=9090` |

### Logging

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OPENTDF_LOG_LEVEL` | Logging level (debug, info, warn, error) | info | `OPENTDF_LOG_LEVEL=debug` |
| `OPENTDF_SECURITY_LOG` | Enable security event logging | true | `OPENTDF_SECURITY_LOG=false` |
| `OPENTDF_SECURITY_LOG_FILE` | Path to security log file (if not set, logs to stderr) | none | `OPENTDF_SECURITY_LOG_FILE=/var/log/opentdf/security.log` |

### Error Handling

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `OPENTDF_ERROR_SANITIZATION` | Level of sanitization for error messages (none, standard, high) | standard | `OPENTDF_ERROR_SANITIZATION=high` |

## Configuration Examples

### Development Environment

```bash
export OPENTDF_MAX_FILE_SIZE=1048576
export OPENTDF_LOG_LEVEL=debug
export OPENTDF_SECURE_DELETE_PASSES=1
export OPENTDF_RATE_LIMIT=1000
export OPENTDF_ERROR_SANITIZATION=none
```

### Production Environment

```bash
export OPENTDF_MAX_FILE_SIZE=104857600
export OPENTDF_LOG_LEVEL=info
export OPENTDF_SECURE_DELETE_PASSES=3
export OPENTDF_RATE_LIMIT=100
export OPENTDF_BURST_LIMIT=20
export OPENTDF_ENABLE_METRICS=true
export OPENTDF_METRICS_PORT=9091
export OPENTDF_SECURITY_LOG=true
export OPENTDF_SECURITY_LOG_FILE=/var/log/opentdf/security.log
export OPENTDF_ERROR_SANITIZATION=standard
```

### High-Security Environment

```bash
export OPENTDF_MAX_FILE_SIZE=52428800
export OPENTDF_LOG_LEVEL=info
export OPENTDF_SECURE_DELETE_PASSES=7
export OPENTDF_RATE_LIMIT=50
export OPENTDF_BURST_LIMIT=10
export OPENTDF_ENABLE_METRICS=true
export OPENTDF_METRICS_PORT=9091
export OPENTDF_SECURITY_LOG=true
export OPENTDF_SECURITY_LOG_FILE=/var/log/opentdf/security.log
export OPENTDF_ERROR_SANITIZATION=high
```

## Performance Tuning

### Memory Usage Optimization

Memory usage is primarily affected by the following configuration options:

- **OPENTDF_MAX_FILE_SIZE**: Directly impacts memory usage as files are loaded into memory during operations.
- **OPENTDF_SECURE_DELETE_BUFFER**: Controls the buffer size for secure deletion operations.

For systems with limited memory, reduce these values:

```bash
export OPENTDF_MAX_FILE_SIZE=10485760  # 10MB
export OPENTDF_SECURE_DELETE_BUFFER=4096
```

### CPU Optimization

CPU usage is primarily affected by:

- **OPENTDF_SECURE_DELETE_PASSES**: More passes mean more CPU usage during secure deletion.

For systems with limited CPU resources, reduce this value:

```bash
export OPENTDF_SECURE_DELETE_PASSES=1
```

### Throughput Optimization

To maximize throughput:

```bash
export OPENTDF_RATE_LIMIT=500
export OPENTDF_BURST_LIMIT=50
export OPENTDF_SECURE_DELETE_PASSES=1
```

## Security Configuration

### Minimal Security (Development)

```bash
export OPENTDF_SECURE_DELETE_PASSES=1
export OPENTDF_ERROR_SANITIZATION=none
export OPENTDF_SECURITY_LOG=false
```

### Standard Security (Production)

```bash
export OPENTDF_SECURE_DELETE_PASSES=3
export OPENTDF_ERROR_SANITIZATION=standard
export OPENTDF_SECURITY_LOG=true
export OPENTDF_RATE_LIMIT=100
```

### Maximum Security (High-Security Environments)

```bash
export OPENTDF_SECURE_DELETE_PASSES=7
export OPENTDF_ERROR_SANITIZATION=high
export OPENTDF_SECURITY_LOG=true
export OPENTDF_SECURITY_LOG_FILE=/var/log/opentdf/security.log
export OPENTDF_RATE_LIMIT=50
export OPENTDF_BURST_LIMIT=10
```

## Monitoring and Metrics

OpenTDF-RS provides Prometheus-compatible metrics on the configured metrics port. Key metrics include:

- `opentdf_secure_delete_duration_ms`: Histogram of secure deletion operation durations
- `opentdf_secure_delete_operations`: Counter of secure deletion operations
- `opentdf_secure_delete_failures`: Counter of secure deletion failures
- `opentdf_errors`: Counter of errors by type
- `opentdf_request_rate`: Rate of incoming requests
- `opentdf_request_duration_ms`: Histogram of request durations

Example Grafana dashboard query for secure deletion performance:

```
histogram_quantile(0.95, sum(rate(opentdf_secure_delete_duration_ms_bucket[5m])) by (le))
```

## Docker Deployment

For Docker deployments, set environment variables in your `docker-compose.yml` file:

```yaml
version: '3'
services:
  opentdf-mcp-server:
    image: opentdf/mcp-server:latest
    environment:
      - OPENTDF_MAX_FILE_SIZE=104857600
      - OPENTDF_LOG_LEVEL=info
      - OPENTDF_SECURE_DELETE_PASSES=3
      - OPENTDF_ENABLE_METRICS=true
      - OPENTDF_METRICS_PORT=9091
    ports:
      - "9091:9091"
    volumes:
      - /var/log/opentdf:/var/log/opentdf
```

## Kubernetes ConfigMap

For Kubernetes deployments, create a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: opentdf-mcp-server-config
data:
  OPENTDF_MAX_FILE_SIZE: "104857600"
  OPENTDF_LOG_LEVEL: "info"
  OPENTDF_SECURE_DELETE_PASSES: "3"
  OPENTDF_ENABLE_METRICS: "true"
  OPENTDF_METRICS_PORT: "9091"
  OPENTDF_SECURITY_LOG: "true"
```

Then reference it in your Deployment:

```yaml
spec:
  containers:
  - name: opentdf-mcp-server
    image: opentdf/mcp-server:latest
    envFrom:
      - configMapRef:
          name: opentdf-mcp-server-config
```