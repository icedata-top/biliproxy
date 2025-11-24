# Prometheus Metrics

The `biliproxy` application exposes Prometheus metrics at the `/metrics` endpoint. These metrics can be scraped by a Prometheus server and visualized in Grafana.

## Exposed Metrics

All metrics are prefixed with `biliproxy_`.

### Default Metrics
The application exports default Node.js metrics provided by `prom-client`, including:
- `biliproxy_process_cpu_user_seconds_total`: Total user CPU time spent in seconds.
- `biliproxy_process_cpu_system_seconds_total`: Total system CPU time spent in seconds.
- `biliproxy_process_resident_memory_bytes`: Resident memory size in bytes.
- `biliproxy_nodejs_eventloop_lag_seconds`: Lag of event loop in seconds.
- ...and others.

### Custom Metrics

#### `biliproxy_http_request_duration_ms`
- **Type**: Histogram
- **Description**: Duration of HTTP requests in milliseconds.
- **Labels**:
  - `method`: HTTP method (e.g., GET, POST)
  - `route`: The route path (e.g., `/x/web-interface/nav`)
  - `code`: HTTP status code (e.g., 200, 404)
- **Buckets**: 100, 300, 500, 700, 1000, 3000, 5000, 7000, 10000

#### `biliproxy_http_response_bytes_total`
- **Type**: Counter
- **Description**: Total number of bytes sent in responses.
- **Labels**:
  - `method`: HTTP method
  - `route`: The route path
  - `code`: HTTP status code

## Example PromQL Queries

### Request Rate (Requests per second)
```promql
rate(biliproxy_http_request_duration_ms_count[1m])
```

### Error Rate (Percentage of non-200 responses)
```promql
sum(rate(biliproxy_http_request_duration_ms_count{code!="200"}[1m])) / sum(rate(biliproxy_http_request_duration_ms_count[1m])) * 100
```

### 99th Percentile Request Latency
```promql
histogram_quantile(0.99, sum(rate(biliproxy_http_request_duration_ms_bucket[1m])) by (le))
```

### Throughput (Megabits per second)
```promql
rate(biliproxy_http_response_bytes_total[1m]) * 8 / 1000 / 1000
```
