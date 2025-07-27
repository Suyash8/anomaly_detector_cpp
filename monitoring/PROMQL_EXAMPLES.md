# PromQL Query Examples for Anomaly Detector

This document provides a comprehensive collection of PromQL queries for monitoring and analyzing the Anomaly Detector system.

## Basic Metrics Queries

### System Health

```promql
# Service availability
up{job="anomaly-detector"}

# Instance count
count(up{job="anomaly-detector"})

# Service uptime
(time() - process_start_time_seconds{job="anomaly-detector"}) / 3600
```

### Processing Metrics

```promql
# Current processing rate (logs per second)
sum(rate(anomaly_detector_logs_processed_total[5m]))

# Processing rate by instance
sum by (instance) (rate(anomaly_detector_logs_processed_total[5m]))

# Total logs processed
sum(anomaly_detector_logs_processed_total)

# Processing latency percentiles
histogram_quantile(0.50, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m])) by (le))
histogram_quantile(0.95, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m])) by (le))
histogram_quantile(0.99, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m])) by (le))

# Average processing duration
sum(rate(anomaly_detector_log_processing_duration_ms_sum[5m])) / sum(rate(anomaly_detector_log_processing_duration_ms_count[5m]))
```

## Performance Analysis

### Resource Utilization

```promql
# CPU usage percentage
anomaly_detector_cpu_usage_percent

# Memory utilization
(anomaly_detector_memory_allocated_bytes / anomaly_detector_memory_pool_size_bytes) * 100

# Memory growth rate (bytes per hour)
rate(anomaly_detector_memory_allocated_bytes[1h]) * 3600

# Disk space usage
anomaly_detector_disk_usage_percent
```

### Threading and Concurrency

```promql
# Thread pool utilization
(anomaly_detector_active_threads / anomaly_detector_thread_pool_size) * 100

# Thread efficiency (tasks per thread per second)
sum(rate(anomaly_detector_logs_processed_total[5m])) / anomaly_detector_active_threads

# Queue depth analysis
anomaly_detector_input_queue_size
anomaly_detector_processing_queue_size
anomaly_detector_alert_queue_size

# Queue processing efficiency
rate(anomaly_detector_logs_processed_total[5m]) / anomaly_detector_input_queue_size
```

### Error Analysis

```promql
# Overall error rate
(sum(rate(anomaly_detector_processing_errors_total[5m])) / sum(rate(anomaly_detector_logs_processed_total[5m]))) * 100

# Error rate by type
sum by (error_type) (rate(anomaly_detector_processing_errors_total[5m]))

# Top error sources
topk(10, sum by (error_type) (rate(anomaly_detector_processing_errors_total[1h])))

# Error trends
increase(anomaly_detector_processing_errors_total[1h])
```

## Security Analysis

### Alert Generation

```promql
# Alert generation rate
sum(rate(anomaly_detector_alerts_generated_total[5m]))

# Alerts by severity
sum by (severity) (rate(anomaly_detector_alerts_generated_total[5m]))

# Critical alerts per minute
sum(rate(anomaly_detector_alerts_generated_total{severity="critical"}[5m])) * 60

# Alert volume by source IP
sum by (source_ip) (rate(anomaly_detector_alerts_generated_total[5m]))

# Top attacking sources
topk(10, sum by (source_ip) (increase(anomaly_detector_alerts_generated_total[1h])))
```

### Threat Analysis

```promql
# Active attack sources (sources generating alerts)
count(count by (source_ip) (rate(anomaly_detector_alerts_generated_total[10m]) > 0))

# Most targeted paths
topk(10, sum by (target_path) (increase(anomaly_detector_alerts_generated_total[1h])))

# Attack pattern distribution
sum by (attack_type) (rate(anomaly_detector_alerts_generated_total[5m]))

# Geographic attack distribution (if geo labels available)
sum by (country) (rate(anomaly_detector_alerts_generated_total[5m]))
```

### Rule Engine Performance

```promql
# Rule evaluations per second by tier
sum by (tier) (rate(anomaly_detector_rule_evaluations_total[5m]))

# Rule efficiency (evaluations per alert)
sum(rate(anomaly_detector_rule_evaluations_total[5m])) / sum(rate(anomaly_detector_alerts_generated_total[5m]))

# Rule hit rate by tier
sum by (tier) (rate(anomaly_detector_alerts_generated_total[5m])) / sum by (tier) (rate(anomaly_detector_rule_evaluations_total[5m]))

# Rule processing latency
sum by (tier) (rate(anomaly_detector_rule_processing_duration_ms_sum[5m])) / sum by (tier) (rate(anomaly_detector_rule_processing_duration_ms_count[5m]))
```

## Dynamic Learning Analysis

### Learning Performance

```promql
# Baseline update rate
rate(anomaly_detector_learning_baseline_updates_total[5m])

# Threshold adjustment frequency
rate(anomaly_detector_learning_threshold_changes_total[5m])

# Learning confidence score
anomaly_detector_learning_confidence_score

# Model training frequency
rate(anomaly_detector_learning_model_updates_total[1h])

# Learning effectiveness (threshold changes per new pattern)
rate(anomaly_detector_learning_threshold_changes_total[1h]) / rate(anomaly_detector_learning_pattern_discoveries_total[1h])
```

### Adaptive Behavior

```promql
# Pattern discovery rate
rate(anomaly_detector_learning_pattern_discoveries_total[5m])

# False positive reduction over time
rate(anomaly_detector_learning_false_positive_adjustments_total[1h])

# Model accuracy improvements
rate(anomaly_detector_learning_accuracy_improvements_total[1h])

# Adaptation speed (time to adjust to new patterns)
changes(anomaly_detector_learning_threshold_changes_total[10m])
```

## Operational Queries

### Capacity Planning

```promql
# Predicted daily volume
predict_linear(anomaly_detector_logs_processed_total[6h], 24*3600)

# Resource scaling indicators
(
  predict_linear(anomaly_detector_cpu_usage_percent[2h], 3600) > 90 or
  predict_linear((anomaly_detector_memory_allocated_bytes / anomaly_detector_memory_pool_size_bytes) * 100[2h], 3600) > 90
)

# Processing capacity utilization
(sum(rate(anomaly_detector_logs_processed_total[5m])) / anomaly_detector_max_processing_rate) * 100

# Queue growth trend
deriv(anomaly_detector_input_queue_size[30m])
```

### SLA Monitoring

```promql
# Processing SLA compliance (< 500ms for 95% of requests)
histogram_quantile(0.95, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m])) by (le)) < 500

# Availability SLA (99.9% uptime)
(sum(rate(up{job="anomaly-detector"}[24h])) / count(up{job="anomaly-detector"})) * 100 > 99.9

# Alert delivery SLA (< 10% failure rate)
(sum(rate(anomaly_detector_alerts_delivery_failed_total[5m])) / sum(rate(anomaly_detector_alerts_delivered_total[5m]))) * 100 < 10

# Response time SLA (detection within 30 seconds)
sum(rate(anomaly_detector_detection_delay_seconds_bucket{le="30"}[5m])) / sum(rate(anomaly_detector_detection_delay_seconds_count[5m])) * 100 > 95
```

## Advanced Analytics

### Anomaly Detection on Metrics

```promql
# Detect unusual processing patterns
abs(
  sum(rate(anomaly_detector_logs_processed_total[5m])) -
  sum(rate(anomaly_detector_logs_processed_total[5m] offset 1w))
) / sum(rate(anomaly_detector_logs_processed_total[5m] offset 1w)) > 0.5

# Memory leak detection
increase(anomaly_detector_memory_allocated_bytes[1h]) > 1073741824  # 1GB increase

# Performance degradation detection
(
  histogram_quantile(0.95, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m])) by (le)) /
  histogram_quantile(0.95, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m] offset 1h)) by (le))
) > 1.5
```

### Correlation Analysis

```promql
# Alert volume correlation with processing load
sum(rate(anomaly_detector_alerts_generated_total[5m])) / sum(rate(anomaly_detector_logs_processed_total[5m]))

# Error correlation with resource usage
sum(rate(anomaly_detector_processing_errors_total[5m])) and on() anomaly_detector_cpu_usage_percent > 80

# Learning effectiveness vs alert accuracy
rate(anomaly_detector_learning_threshold_changes_total[1h]) / rate(anomaly_detector_alerts_false_positives_total[1h])
```

### Business Intelligence

```promql
# Security posture score
100 - (sum(rate(anomaly_detector_alerts_generated_total{severity=~"critical|high"}[1h])) * 10)

# Cost efficiency (alerts per resource unit)
sum(rate(anomaly_detector_alerts_generated_total[5m])) / (anomaly_detector_cpu_usage_percent + (anomaly_detector_memory_allocated_bytes / 1073741824))

# System reliability index
(
  (sum(rate(up{job="anomaly-detector"}[24h])) / count(up{job="anomaly-detector"})) * 0.4 +
  ((100 - ((sum(rate(anomaly_detector_processing_errors_total[24h])) / sum(rate(anomaly_detector_logs_processed_total[24h]))) * 100)) / 100) * 0.3 +
  (100 - anomaly_detector_cpu_usage_percent) / 100 * 0.3
) * 100
```

## Alerting Queries

### Critical Conditions

```promql
# Service completely down
up{job="anomaly-detector"} == 0

# Critical processing failure
sum(rate(anomaly_detector_processing_errors_total[5m])) / sum(rate(anomaly_detector_logs_processed_total[5m])) > 0.1

# Memory exhaustion
(anomaly_detector_memory_allocated_bytes / anomaly_detector_memory_pool_size_bytes) * 100 > 95

# Processing completely stalled
sum(rate(anomaly_detector_logs_processed_total[5m])) == 0 and sum(anomaly_detector_input_queue_size) > 0
```

### Warning Conditions

```promql
# High processing latency
histogram_quantile(0.95, sum(rate(anomaly_detector_log_processing_duration_ms_bucket[5m])) by (le)) > 1000

# High CPU usage
anomaly_detector_cpu_usage_percent > 80

# Growing queue backlog
increase(anomaly_detector_input_queue_size[10m]) > 1000

# High alert volume
sum(rate(anomaly_detector_alerts_generated_total[5m])) > 10
```

## Debugging Queries

### Troubleshooting Performance Issues

```promql
# Identify bottlenecks
topk(5, sum by (component) (rate(anomaly_detector_processing_duration_ms_sum[5m])))

# Thread contention analysis
anomaly_detector_thread_wait_time_ms / anomaly_detector_thread_active_time_ms

# I/O performance
rate(anomaly_detector_disk_read_bytes_total[5m]) + rate(anomaly_detector_disk_write_bytes_total[5m])

# Network performance
rate(anomaly_detector_network_bytes_received_total[5m]) + rate(anomaly_detector_network_bytes_sent_total[5m])
```

### Configuration Analysis

```promql
# Configuration reload frequency
rate(anomaly_detector_config_reloads_total[1h])

# Configuration errors
rate(anomaly_detector_config_errors_total[5m])

# Feature flag usage
anomaly_detector_feature_flags{flag="dynamic_learning"}
```

## Custom Metrics Creation

### Recording Rules Examples

```yaml
# Example recording rules for complex queries
groups:
  - name: anomaly_detector_recording
    interval: 30s
    rules:
      - record: anomaly_detector:processing_rate_5m
        expr: sum(rate(anomaly_detector_logs_processed_total[5m]))

      - record: anomaly_detector:error_rate_5m
        expr: sum(rate(anomaly_detector_processing_errors_total[5m])) / sum(rate(anomaly_detector_logs_processed_total[5m]))

      - record: anomaly_detector:resource_efficiency
        expr: sum(rate(anomaly_detector_logs_processed_total[5m])) / (anomaly_detector_cpu_usage_percent / 100)

      - record: anomaly_detector:security_health_score
        expr: 100 - (sum(rate(anomaly_detector_alerts_generated_total{severity=~"critical|high"}[1h])) * 10)
```

## Query Optimization Tips

### Performance Best Practices

1. **Use recording rules** for frequently used complex queries
2. **Limit time ranges** for expensive operations
3. **Use appropriate step intervals** in range queries
4. **Leverage label filtering** early in queries
5. **Avoid unnecessary regex operations**

### Efficient Query Patterns

```promql
# Good: Specific label filtering
sum(rate(anomaly_detector_logs_processed_total{instance="prod-1"}[5m]))

# Bad: Broad regex filtering
sum(rate(anomaly_detector_logs_processed_total{instance=~".*"}[5m]))

# Good: Use recording rules for complex calculations
anomaly_detector:processing_rate_5m

# Bad: Complex calculation in every query
sum(rate(anomaly_detector_logs_processed_total[5m])) / avg(anomaly_detector_cpu_usage_percent) * 100
```

This comprehensive collection of PromQL queries provides the foundation for effective monitoring and analysis of the Anomaly Detector system across all operational aspects.
