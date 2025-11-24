import client from 'prom-client';

// Create a Registry which registers the metrics
const register = new client.Registry();

// Add a default label which is added to all metrics
register.setDefaultLabels({
    app: 'biliproxy'
});

// Enable the collection of default metrics with prefix
client.collectDefaultMetrics({ register, prefix: 'biliproxy_' });

// Create a histogram metric
const httpRequestDurationMs = new client.Histogram({
    name: 'biliproxy_http_request_duration_ms',
    help: 'Duration of HTTP requests in milliseconds',
    labelNames: ['method', 'route', 'code'],
    buckets: [100, 300, 500, 700, 1000, 3000, 5000, 7000, 10000]
});

// Create a counter metric for response bytes
const httpResponseBytesTotal = new client.Counter({
    name: 'biliproxy_http_response_bytes_total',
    help: 'Total number of bytes sent in responses',
    labelNames: ['method', 'route', 'code']
});

// Register the metrics
register.registerMetric(httpRequestDurationMs);
register.registerMetric(httpResponseBytesTotal);

export {
    register,
    httpRequestDurationMs,
    httpResponseBytesTotal
};
