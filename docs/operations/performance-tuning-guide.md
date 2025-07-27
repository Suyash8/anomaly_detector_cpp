# Performance Tuning Guide

This guide provides comprehensive recommendations for optimizing the Anomaly Detector system performance across different deployment scenarios and workloads.

## Table of Contents

1. [Performance Baselines](#performance-baselines)
2. [System Resource Optimization](#system-resource-optimization)
3. [Application Configuration Tuning](#application-configuration-tuning)
4. [Memory Management Optimization](#memory-management-optimization)
5. [Rule Engine Performance](#rule-engine-performance)
6. [Database and Storage Optimization](#database-and-storage-optimization)
7. [Network Performance Tuning](#network-performance-tuning)
8. [Monitoring and Profiling](#monitoring-and-profiling)
9. [Scaling Strategies](#scaling-strategies)
10. [Environment-Specific Optimizations](#environment-specific-optimizations)

## Performance Baselines

### Target Performance Metrics

#### Processing Performance

- **Log Processing Rate**: 10,000+ logs/second (sustained)
- **Processing Latency**: P95 < 100ms, P99 < 500ms
- **Memory Usage**: < 4GB for standard deployment
- **CPU Utilization**: < 70% average, < 90% peak
- **Alert Generation**: < 50ms from detection to alert

#### Throughput Targets by Deployment Size

| Deployment Size | Logs/Second | Memory Limit | CPU Cores | Disk IOPS |
| --------------- | ----------- | ------------ | --------- | --------- |
| Small           | 1,000       | 2GB          | 4         | 1,000     |
| Medium          | 5,000       | 8GB          | 8         | 5,000     |
| Large           | 15,000      | 16GB         | 16        | 10,000    |
| Enterprise      | 50,000+     | 32GB+        | 32+       | 20,000+   |

### Performance Testing Framework

#### Benchmark Script

```bash
#!/bin/bash
# performance-benchmark.sh

set -e

DURATION=${1:-300}  # 5 minutes default
LOG_RATE=${2:-1000} # logs per second

echo "Starting performance benchmark..."
echo "Duration: ${DURATION}s, Target rate: ${LOG_RATE} logs/sec"

# Start metrics collection
start_time=$(date +%s)
start_logs=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')
start_memory=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_memory_allocated_bytes" | awk '{print $2}')

# Generate load
generate_load() {
    local rate=$1
    local duration=$2
    local interval=$(echo "scale=3; 1.0 / $rate" | bc)

    for ((i=1; i<=duration*rate; i++)); do
        echo "$(date '+%d/%b/%Y:%H:%M:%S %z') \"GET /api/test/$i HTTP/1.1\" 200 $((RANDOM % 10000 + 1000)) 192.168.1.$((RANDOM % 254 + 1))" >> /tmp/perf_test.log
        sleep $interval
    done
}

# Run load generation in background
generate_load $LOG_RATE $DURATION &
LOAD_PID=$!

# Monitor performance
monitor_performance() {
    while kill -0 $LOAD_PID 2>/dev/null; do
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        logs_processed=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')
        memory_used=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_memory_allocated_bytes" | awk '{print $2}')
        cpu_usage=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_cpu_usage_percent" | awk '{print $2}')
        latency_p95=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_log_processing_duration_ms" | grep "quantile=\"0.95\"" | awk '{print $2}')

        echo "$timestamp,$logs_processed,$memory_used,$cpu_usage,$latency_p95" >> performance_metrics.csv
        sleep 5
    done
}

# Start monitoring
echo "timestamp,logs_processed,memory_bytes,cpu_percent,latency_p95_ms" > performance_metrics.csv
monitor_performance &
MONITOR_PID=$!

# Wait for load generation to complete
wait $LOAD_PID

# Stop monitoring
kill $MONITOR_PID 2>/dev/null || true

# Calculate results
end_time=$(date +%s)
end_logs=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')
end_memory=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_memory_allocated_bytes" | awk '{print $2}')

total_logs=$((end_logs - start_logs))
actual_duration=$((end_time - start_time))
actual_rate=$(echo "scale=2; $total_logs / $actual_duration" | bc)
memory_delta=$(echo "scale=2; ($end_memory - $start_memory) / 1024 / 1024" | bc)

echo "=== Performance Benchmark Results ==="
echo "Duration: ${actual_duration}s"
echo "Logs processed: $total_logs"
echo "Actual processing rate: ${actual_rate} logs/sec"
echo "Memory growth: ${memory_delta}MB"
echo "Detailed metrics saved to: performance_metrics.csv"

# Cleanup
rm -f /tmp/perf_test.log
```

## System Resource Optimization

### CPU Optimization

#### CPU Affinity Configuration

```bash
# Pin anomaly detector to specific CPU cores
sudo systemctl edit anomaly-detector
# Add:
[Service]
ExecStart=
ExecStart=/usr/bin/taskset -c 0-7 /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini
```

#### CPU Governor Settings

```bash
# Set CPU governor to performance mode
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee $cpu
done

# Disable CPU frequency scaling
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
```

#### NUMA Optimization

```bash
# Check NUMA topology
numactl --hardware

# Run with NUMA optimization
numactl --cpunodebind=0 --membind=0 /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini
```

### Memory Optimization

#### System Memory Settings

```bash
# Optimize memory overcommit
echo 1 | sudo tee /proc/sys/vm/overcommit_memory
echo 50 | sudo tee /proc/sys/vm/overcommit_ratio

# Reduce swappiness
echo 10 | sudo tee /proc/sys/vm/swappiness

# Optimize dirty page handling
echo 10 | sudo tee /proc/sys/vm/dirty_ratio
echo 5 | sudo tee /proc/sys/vm/dirty_background_ratio
```

#### Huge Pages Configuration

```bash
# Enable transparent huge pages
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/defrag

# Pre-allocate huge pages (optional)
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages
```

### I/O Optimization

#### Disk I/O Scheduler

```bash
# Set I/O scheduler to deadline for SSDs
echo deadline | sudo tee /sys/block/sda/queue/scheduler

# Or use mq-deadline for NVMe drives
echo mq-deadline | sudo tee /sys/block/nvme0n1/queue/scheduler

# Optimize read-ahead for log files
echo 4096 | sudo tee /sys/block/sda/queue/read_ahead_kb
```

#### File System Optimization

```bash
# Mount with optimized options for log processing
# Add to /etc/fstab:
/dev/sda1 /var/log ext4 defaults,noatime,data=writeback,barrier=0 0 2

# Remount with new options
sudo mount -o remount /var/log
```

## Application Configuration Tuning

### Worker Thread Optimization

#### Thread Count Calculation

```ini
[general]
# Formula: (CPU cores * 2) for I/O bound workloads
# Formula: (CPU cores) for CPU bound workloads
worker_threads = 16  # For 8-core system with I/O bound processing

# Enable thread affinity
enable_thread_affinity = true
thread_affinity_mask = "0-15"  # Use cores 0-15
```

#### Thread Pool Configuration

```ini
[threading]
# Optimize thread pool behavior
thread_pool_size = 16
thread_queue_size = 10000
thread_idle_timeout = 30

# Enable work-stealing for better load distribution
enable_work_stealing = true
steal_attempts = 3
```

### Queue Management

#### Queue Size Optimization

```ini
[performance]
# Increase queue sizes for high-throughput scenarios
max_input_queue_size = 200000   # Increase from 100000
max_processing_queue_size = 50000
max_alert_queue_size = 10000

# Enable queue monitoring
enable_queue_monitoring = true
queue_warning_threshold = 0.8
```

#### Batch Processing

```ini
[log_sources]
# Optimize batch sizes for better throughput
batch_size = 5000              # Increase from 1000
batch_timeout_ms = 100         # Maximum wait time for batch
max_batch_memory_mb = 100      # Memory limit per batch

# Enable batch compression
enable_batch_compression = true
compression_threshold = 1000
```

### Memory Pool Configuration

#### Object Pool Tuning

```ini
[memory_management]
# Optimize pool sizes based on workload
pool_sizes = {
    "LogEntry": 50000,         # Increase for high log volume
    "AnalyzedEvent": 25000,    # Based on processing rate
    "PerIPState": 10000,       # Based on unique IP count
    "PerPathState": 5000,      # Based on unique path count
    "PerSessionState": 2000    # Based on concurrent sessions
}

# Pool management settings
pool_growth_factor = 1.5       # How much to grow pools
pool_shrink_threshold = 0.3    # When to shrink pools
pool_maintenance_interval = 60 # Seconds between maintenance
```

#### Memory Allocation Strategy

```ini
[memory_management]
# Use memory-mapped allocation for large objects
enable_mmap_allocation = true
mmap_threshold_bytes = 1048576  # 1MB threshold

# Pre-allocate memory pools
preallocate_pools = true
preallocation_percentage = 0.8

# Memory compaction settings
enable_memory_compaction = true
compaction_trigger_threshold = 0.7
compaction_interval = 300
```

## Memory Management Optimization

### Garbage Collection Tuning

#### Eviction Policy Configuration

```ini
[memory_management]
# LRU eviction configuration
eviction_policy = "lru"
eviction_threshold = 0.85
eviction_batch_size = 1000
eviction_interval = 30

# TTL-based cleanup
enable_ttl_cleanup = true
default_ttl_seconds = 3600
cleanup_interval = 300

# Aggressive cleanup under pressure
enable_pressure_cleanup = true
pressure_threshold = 0.95
pressure_cleanup_percentage = 0.2
```

#### Memory Monitoring

```ini
[monitoring]
# Memory pressure monitoring
enable_memory_monitoring = true
monitoring_interval = 15
memory_warning_threshold = 0.8
memory_critical_threshold = 0.9

# Automatic memory reporting
auto_memory_reports = true
report_interval = 300
detailed_reports = false
```

### State Object Optimization

#### State Compression

```ini
[state_management]
# Enable state compression
enable_state_compression = true
compression_algorithm = "lz4"  # or "zstd", "gzip"
compression_threshold = 1024   # Bytes

# Bloom filter optimization
bloom_filter_size = 1000000    # 1M entries
bloom_filter_hash_functions = 3
bloom_filter_false_positive_rate = 0.01
```

#### State Persistence

```ini
[persistence]
# Optimize state persistence
enable_state_persistence = true
persistence_interval = 600      # 10 minutes
persistence_batch_size = 10000
use_async_persistence = true

# Compression for persistent data
enable_persistence_compression = true
persistence_compression_level = 6
```

## Rule Engine Performance

### Rule Evaluation Optimization

#### Tier-based Optimization

```ini
[rule_engine]
# Optimize evaluation order (fastest to slowest)
evaluation_order = ["tier1", "tier2", "tier3", "tier4"]

# Skip expensive tiers under high load
enable_tier_skipping = true
cpu_threshold_for_skipping = 80
skip_tier3_threshold = 85
skip_tier4_threshold = 90

# Parallel evaluation within tiers
enable_parallel_evaluation = true
max_parallel_evaluations = 4
```

#### Rule Caching

```ini
[rule_caching]
# Enable rule result caching
enable_rule_caching = true
cache_size = 100000
cache_ttl = 300

# Cache hit optimization
enable_cache_warming = true
cache_prefetch_percentage = 0.1

# Cache statistics
enable_cache_stats = true
stats_reporting_interval = 300
```

### Dynamic Learning Optimization

#### Learning Rate Tuning

```ini
[dynamic_learning]
# Optimize learning parameters
learning_rate = 0.05           # Slower learning for stability
confidence_threshold = 0.85    # Higher confidence requirement
update_frequency = 60          # Update every minute

# Seasonal pattern optimization
enable_seasonal_patterns = true
seasonal_window_hours = 168    # 1 week
seasonal_confidence_threshold = 0.9

# Baseline management
baseline_retention_days = 30
baseline_cleanup_interval = 3600
enable_baseline_compression = true
```

#### Statistical Optimization

```ini
[statistics]
# Rolling statistics configuration
rolling_window_size = 1000
statistics_decay_factor = 0.99
outlier_detection_threshold = 3.0

# Performance optimizations
enable_fast_statistics = true
use_approximate_algorithms = true
statistics_update_batch_size = 100
```

## Database and Storage Optimization

### File System Performance

#### Log File Optimization

```bash
# Optimize log rotation for performance
# /etc/logrotate.d/application-logs
/var/log/application/*.log {
    hourly
    rotate 24
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        /bin/kill -HUP $(cat /var/run/anomaly-detector.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

#### Storage Configuration

```ini
[storage]
# Optimize storage settings
storage_backend = "file"       # or "memory", "hybrid"
storage_path = "/var/lib/anomaly-detector"
enable_storage_compression = true

# Write optimization
write_batch_size = 10000
write_sync_interval = 30
enable_write_coalescing = true

# Read optimization
read_ahead_size = 4096
enable_read_caching = true
read_cache_size_mb = 256
```

### Data Retention

#### Retention Policies

```ini
[data_retention]
# Optimize data retention for performance
raw_logs_retention_days = 7
processed_events_retention_days = 30
alerts_retention_days = 90
statistics_retention_days = 365

# Cleanup optimization
cleanup_batch_size = 10000
cleanup_interval = 3600
enable_background_cleanup = true
```

## Network Performance Tuning

### TCP Optimization

#### System-level TCP Tuning

```bash
# Optimize TCP settings for high throughput
cat >> /etc/sysctl.conf << EOF
# TCP buffer sizes
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# TCP window scaling
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP congestion control
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Connection handling
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 4096
EOF

sudo sysctl -p
```

#### Application Network Settings

```ini
[network]
# Optimize network configuration
tcp_nodelay = true
tcp_keepalive = true
connection_timeout = 30
read_timeout = 60
write_timeout = 30

# Connection pooling
enable_connection_pooling = true
max_connections_per_host = 100
connection_idle_timeout = 300
```

### Prometheus Integration Optimization

#### Query Optimization

```ini
[prometheus]
# Optimize Prometheus queries
query_timeout = 60
max_concurrent_queries = 10
query_batch_size = 100

# Connection optimization
connection_pool_size = 20
keep_alive_timeout = 300
max_idle_connections = 5

# Caching
enable_query_caching = true
cache_ttl = 60
cache_size = 1000
```

## Monitoring and Profiling

### Performance Monitoring

#### Metrics Collection

```ini
[metrics]
# Enable detailed performance metrics
enable_performance_metrics = true
metrics_collection_interval = 15
enable_histogram_metrics = true

# Profiling
enable_cpu_profiling = false    # Enable only when needed
enable_memory_profiling = false # Enable only when needed
profiling_interval = 300
```

#### Custom Monitoring Script

```bash
#!/bin/bash
# performance-monitor.sh

METRICS_ENDPOINT="http://localhost:8080/metrics"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_LATENCY=1000

while true; do
    # Collect metrics
    CPU_USAGE=$(curl -s $METRICS_ENDPOINT | grep "anomaly_detector_cpu_usage_percent" | awk '{print $2}')
    MEMORY_USAGE=$(curl -s $METRICS_ENDPOINT | grep "anomaly_detector_memory_usage_percent" | awk '{print $2}')
    LATENCY_P95=$(curl -s $METRICS_ENDPOINT | grep "anomaly_detector_processing_latency_p95" | awk '{print $2}')
    PROCESSING_RATE=$(curl -s $METRICS_ENDPOINT | grep "anomaly_detector_processing_rate" | awk '{print $2}')

    # Check thresholds
    if (( $(echo "$CPU_USAGE > $ALERT_THRESHOLD_CPU" | bc -l) )); then
        echo "WARNING: High CPU usage: ${CPU_USAGE}%"
    fi

    if (( $(echo "$MEMORY_USAGE > $ALERT_THRESHOLD_MEMORY" | bc -l) )); then
        echo "WARNING: High memory usage: ${MEMORY_USAGE}%"
    fi

    if (( $(echo "$LATENCY_P95 > $ALERT_THRESHOLD_LATENCY" | bc -l) )); then
        echo "WARNING: High processing latency: ${LATENCY_P95}ms"
    fi

    # Log current status
    echo "$(date): CPU=${CPU_USAGE}%, MEM=${MEMORY_USAGE}%, LAT=${LATENCY_P95}ms, RATE=${PROCESSING_RATE}/s"

    sleep 60
done
```

### Profiling Tools

#### CPU Profiling

```bash
# Profile CPU usage during high load
sudo perf record -g -p $(pgrep anomaly_detector) sleep 60
sudo perf report --stdio > cpu_profile.txt

# Continuous CPU monitoring
sudo perf top -p $(pgrep anomaly_detector)
```

#### Memory Profiling

```bash
# Memory usage analysis
sudo pmap -x $(pgrep anomaly_detector)

# Memory leak detection
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
    /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini
```

## Scaling Strategies

### Vertical Scaling

#### Resource Scaling Guidelines

```bash
# Calculate optimal resource allocation
calculate_resources() {
    local target_logs_per_sec=$1

    # CPU cores (rule of thumb: 1000 logs/sec per core)
    cpu_cores=$(echo "scale=0; ($target_logs_per_sec / 1000) + 1" | bc)

    # Memory (rule of thumb: 2GB base + 1GB per 2000 logs/sec)
    memory_gb=$(echo "scale=0; 2 + ($target_logs_per_sec / 2000)" | bc)

    # Disk IOPS (rule of thumb: 1 IOPS per log/sec)
    disk_iops=$target_logs_per_sec

    echo "For $target_logs_per_sec logs/sec:"
    echo "  CPU cores: $cpu_cores"
    echo "  Memory: ${memory_gb}GB"
    echo "  Disk IOPS: $disk_iops"
}

# Example usage
calculate_resources 10000
```

### Horizontal Scaling

#### Load Balancer Configuration

```yaml
# nginx load balancer config
upstream anomaly_detectors {
least_conn;
server anomaly-detector-1:8080 max_fails=3 fail_timeout=30s;
server anomaly-detector-2:8080 max_fails=3 fail_timeout=30s;
server anomaly-detector-3:8080 max_fails=3 fail_timeout=30s;
}

server {
listen 80;
location /metrics {
proxy_pass http://anomaly_detectors;
proxy_connect_timeout 10s;
proxy_read_timeout 60s;
}
}
```

#### Sharding Strategy

```ini
[sharding]
# Enable log sharding across instances
enable_sharding = true
shard_key = "source_ip"        # or "log_path", "session_id"
shard_count = 4
shard_id = 1                   # Unique per instance

# Consistent hashing
hash_algorithm = "sha256"
virtual_nodes = 150
```

## Environment-Specific Optimizations

### Cloud Environment Optimization

#### AWS Optimization

```ini
[aws]
# EC2 instance optimization
enable_placement_groups = true
use_sr_iov = true
enable_enhanced_networking = true

# EBS optimization
ebs_optimized = true
volume_type = "gp3"
provisioned_iops = 10000
```

#### Container Optimization

```yaml
# Docker optimization
services:
  anomaly-detector:
    image: anomaly-detector:latest
    deploy:
      resources:
        limits:
          cpus: "8.0"
          memory: 16G
        reservations:
          cpus: "4.0"
          memory: 8G
    sysctls:
      - net.core.somaxconn=4096
      - net.ipv4.tcp_fin_timeout=30
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

### Bare Metal Optimization

#### Hardware-specific Tuning

```bash
# Intel CPU optimization
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# NUMA binding
numactl --cpunodebind=0 --membind=0 /usr/local/bin/anomaly_detector

# IRQ affinity optimization
echo 2 | sudo tee /proc/irq/24/smp_affinity  # Network interface IRQ
echo 4 | sudo tee /proc/irq/25/smp_affinity  # Disk controller IRQ
```

This performance tuning guide provides comprehensive optimization strategies for maximizing the Anomaly Detector system performance across various deployment scenarios.
