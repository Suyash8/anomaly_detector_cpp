# Troubleshooting Guide

This comprehensive guide provides solutions for common issues encountered when operating the Anomaly Detector system, including diagnostics, debugging procedures, and resolution steps.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Service and Startup Issues](#service-and-startup-issues)
3. [Performance Problems](#performance-problems)
4. [Memory Issues](#memory-issues)
5. [Configuration Problems](#configuration-problems)
6. [Log Processing Issues](#log-processing-issues)
7. [Alert System Problems](#alert-system-problems)
8. [Prometheus Integration Issues](#prometheus-integration-issues)
9. [Network and Connectivity Problems](#network-and-connectivity-problems)
10. [Advanced Debugging](#advanced-debugging)

## Quick Diagnostics

### Health Check Command

```bash
#!/bin/bash
# quick-health-check.sh

echo "=== Anomaly Detector Quick Health Check ==="

# Service status
echo "1. Service Status:"
systemctl is-active anomaly-detector && echo "✓ Service is running" || echo "✗ Service is not running"

# Process check
echo "2. Process Status:"
pgrep anomaly_detector > /dev/null && echo "✓ Process is running" || echo "✗ Process not found"

# Port check
echo "3. Port Status:"
netstat -tuln | grep :8080 > /dev/null && echo "✓ Port 8080 is listening" || echo "✗ Port 8080 not listening"

# Health endpoint
echo "4. Health Endpoint:"
if curl -s -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✓ Health endpoint accessible"
else
    echo "✗ Health endpoint not accessible"
fi

# Metrics endpoint
echo "5. Metrics Endpoint:"
if curl -s http://localhost:8080/metrics | head -1 | grep -q "anomaly_detector"; then
    echo "✓ Metrics are being exported"
else
    echo "✗ Metrics not available"
fi

# Log processing
echo "6. Log Processing:"
CURRENT_COUNT=$(curl -s http://localhost:8080/metrics 2>/dev/null | grep "anomaly_detector_logs_processed_total" | awk '{print $2}' | head -1)
if [[ -n "$CURRENT_COUNT" ]]; then
    echo "✓ Total logs processed: $CURRENT_COUNT"
else
    echo "✗ Cannot retrieve log processing metrics"
fi

# Memory usage
echo "7. Memory Usage:"
MEMORY_USAGE=$(curl -s http://localhost:8080/metrics 2>/dev/null | grep "anomaly_detector_memory_allocated_bytes" | awk '{print $2}' | head -1)
if [[ -n "$MEMORY_USAGE" ]]; then
    echo "✓ Current memory usage: $(echo "$MEMORY_USAGE / 1024 / 1024" | bc)MB"
else
    echo "✗ Cannot retrieve memory metrics"
fi

echo "=== Health Check Complete ==="
```

### Log Analysis

```bash
# View recent logs
sudo journalctl -u anomaly-detector --since "1 hour ago" --no-pager

# View error logs only
sudo journalctl -u anomaly-detector -p err --since "1 hour ago" --no-pager

# Follow live logs
sudo journalctl -u anomaly-detector -f
```

## Service and Startup Issues

### Problem: Service Fails to Start

#### Symptoms

- `systemctl start anomaly-detector` fails
- Service shows "failed" status
- Application exits immediately

#### Diagnostic Steps

```bash
# Check service status
systemctl status anomaly-detector

# Check detailed logs
journalctl -u anomaly-detector --since "10 minutes ago" --no-pager

# Test configuration
sudo -u anomaly-detector /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini --validate-config

# Check file permissions
sudo -u anomaly-detector ls -la /etc/anomaly-detector/
sudo -u anomaly-detector touch /var/lib/anomaly-detector/test
```

#### Common Solutions

**Configuration Syntax Error**

```bash
# Test configuration manually
anomaly_detector --config /etc/anomaly-detector/config.ini --validate-config

# Fix common syntax issues:
# - Missing quotes around strings
# - Invalid section names
# - Duplicate keys
```

**Permission Issues**

```bash
# Fix file permissions
sudo chown -R anomaly-detector:anomaly-detector /var/lib/anomaly-detector
sudo chown -R anomaly-detector:anomaly-detector /var/log/anomaly-detector
sudo chmod 640 /etc/anomaly-detector/config.ini

# Check SELinux (if applicable)
sudo setsebool -P httpd_can_network_connect 1
```

**Missing Dependencies**

```bash
# Check library dependencies
ldd /usr/local/bin/anomaly_detector

# Install missing libraries (Ubuntu/Debian)
sudo apt-get install -y libssl1.1 libcurl4

# Install missing libraries (CentOS/RHEL)
sudo yum install -y openssl-libs libcurl
```

### Problem: Service Starts but Immediately Exits

#### Diagnostic Steps

```bash
# Run manually to see error output
sudo -u anomaly-detector /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini --debug

# Check for resource limits
ulimit -a

# Check disk space
df -h /var/lib/anomaly-detector
df -h /var/log/anomaly-detector
```

#### Common Solutions

**Insufficient Resources**

```bash
# Increase file descriptor limits
echo "anomaly-detector soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "anomaly-detector hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Restart service
sudo systemctl restart anomaly-detector
```

**Port Already in Use**

```bash
# Find process using port 8080
sudo netstat -tlnp | grep :8080
sudo lsof -i :8080

# Kill conflicting process or change port in configuration
```

## Performance Problems

### Problem: High CPU Usage

#### Symptoms

- CPU usage consistently above 80%
- System becomes unresponsive
- Processing latency increases

#### Diagnostic Steps

```bash
# Monitor CPU usage
top -p $(pgrep anomaly_detector)

# Check processing metrics
curl -s http://localhost:8080/metrics | grep -E "(cpu_usage|processing_duration|logs_processed)"

# Profile the application
sudo perf record -p $(pgrep anomaly_detector) sleep 30
sudo perf report
```

#### Solutions

**Reduce Processing Load**

```ini
# Reduce worker threads in config.ini
[general]
worker_threads = 4  # Reduce from higher number

# Increase batch processing
[log_sources]
batch_size = 2000  # Increase from 1000
```

**Optimize Rule Evaluation**

```ini
# Disable expensive tiers temporarily
[rule_engine]
tier4_enabled = false  # Disable Prometheus queries
tier3_enabled = false  # Disable complex patterns

# Increase evaluation intervals
[prometheus]
query_interval = 60  # Increase from 15 seconds
```

### Problem: High Memory Usage

#### Symptoms

- Memory usage constantly growing
- Out of memory errors
- System swapping

#### Diagnostic Steps

```bash
# Check memory metrics
curl -s http://localhost:8080/metrics | grep -E "memory_"

# Monitor memory growth
watch -n 5 'curl -s http://localhost:8080/metrics | grep memory_allocated_bytes'

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini
```

#### Solutions

**Adjust Memory Limits**

```ini
# Reduce memory usage in config.ini
[memory_management]
max_memory_mb = 2048  # Reduce from higher value
eviction_threshold = 0.75  # Reduce from 0.85

# Reduce object pool sizes
pool_sizes = {
    "LogEntry": 5000,     # Reduce from 10000
    "AnalyzedEvent": 2500, # Reduce from 5000
    "PerIPState": 500     # Reduce from 1000
}
```

**Enable Aggressive Cleanup**

```ini
[memory_management]
cleanup_interval = 60  # Reduce from 300 seconds
enable_aggressive_cleanup = true
```

## Memory Issues

### Problem: Memory Leaks

#### Symptoms

- Memory usage continuously increases
- Never decreases even during low activity
- Eventually causes OOM kills

#### Diagnostic Steps

```bash
# Memory leak detection
echo 'set confirm off
run --config /etc/anomaly-detector/config.ini
continue
quit' | gdb /usr/local/bin/anomaly_detector

# Use memory debugging tools
export MALLOC_CHECK_=2
anomaly_detector --config /etc/anomaly-detector/config.ini
```

#### Solutions

**Enable Memory Debugging**

```ini
[debug]
memory_debugging = true
track_allocations = true
dump_memory_stats = true
```

**Implement Workaround**

```bash
# Periodic service restart (temporary solution)
sudo tee /etc/systemd/system/anomaly-detector-restart.timer << EOF
[Unit]
Description=Restart Anomaly Detector every 6 hours

[Timer]
OnBootSec=6h
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
EOF

sudo systemctl enable anomaly-detector-restart.timer
sudo systemctl start anomaly-detector-restart.timer
```

### Problem: Out of Memory Errors

#### Diagnostic Steps

```bash
# Check system memory
free -h

# Check OOM killer logs
dmesg | grep -i "killed process"
sudo journalctl | grep -i "out of memory"

# Monitor memory pressure
cat /proc/pressure/memory
```

#### Solutions

**Increase System Memory**

```bash
# Add swap space (temporary solution)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

**Reduce Memory Usage**

```ini
[memory_management]
max_memory_mb = 1024  # Reduce significantly
enable_memory_pressure_handling = true
pressure_threshold = 0.90
```

## Configuration Problems

### Problem: Configuration Validation Errors

#### Symptoms

- Service fails to start with config errors
- Invalid parameter warnings in logs
- Unexpected behavior due to misconfig

#### Diagnostic Steps

```bash
# Validate configuration syntax
anomaly_detector --config /etc/anomaly-detector/config.ini --validate-config

# Check for required parameters
grep -E "^\s*#|^\s*$" /etc/anomaly-detector/config.ini -v | sort

# Compare with template
diff -u config_templates/production.ini /etc/anomaly-detector/config.ini
```

#### Solutions

**Fix Common Configuration Issues**

```bash
# Fix file format issues
dos2unix /etc/anomaly-detector/config.ini

# Check for special characters
file /etc/anomaly-detector/config.ini
hexdump -C /etc/anomaly-detector/config.ini | head
```

**Restore from Template**

```bash
# Backup current config
sudo cp /etc/anomaly-detector/config.ini /etc/anomaly-detector/config.ini.backup

# Restore from template
sudo cp config_templates/production.ini /etc/anomaly-detector/config.ini

# Migrate settings manually
sudo vim /etc/anomaly-detector/config.ini
```

### Problem: Environment Variable Issues

#### Diagnostic Steps

```bash
# Check environment variables
sudo systemctl show anomaly-detector --property Environment

# Test environment loading
sudo -u anomaly-detector env | grep AD_

# Validate environment file
sudo cat /etc/anomaly-detector/environment
```

#### Solutions

**Fix Environment Variables**

```bash
# Ensure environment file is readable
sudo chmod 640 /etc/anomaly-detector/environment
sudo chown root:anomaly-detector /etc/anomaly-detector/environment

# Test variable substitution
sudo -u anomaly-detector bash -c 'source /etc/anomaly-detector/environment && echo $AD_SMTP_PASSWORD'
```

## Log Processing Issues

### Problem: Logs Not Being Processed

#### Symptoms

- Log processing counter not increasing
- No alerts generated despite suspicious activity
- High queue depth

#### Diagnostic Steps

```bash
# Check log processing metrics
curl -s http://localhost:8080/metrics | grep -E "(logs_processed|queue_size)"

# Verify log file access
sudo -u anomaly-detector cat /var/log/nginx/access.log | head -5

# Check file monitoring
sudo -u anomaly-detector inotifywait -m /var/log/nginx/access.log
```

#### Solutions

**Fix File Permissions**

```bash
# Add user to log group
sudo usermod -a -G adm anomaly-detector

# Make log files readable
sudo chmod 644 /var/log/nginx/access.log
sudo chmod 755 /var/log/nginx/
```

**Check Log Format**

```bash
# Test log parsing manually
echo '127.0.0.1 - - [27/Jul/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 1234' | anomaly_detector --test-parser
```

### Problem: High Queue Backlog

#### Symptoms

- Input queue size constantly growing
- Processing lag increases
- Memory usage increases

#### Diagnostic Steps

```bash
# Monitor queue sizes
watch -n 2 'curl -s http://localhost:8080/metrics | grep queue_size'

# Check processing rate
curl -s http://localhost:8080/metrics | grep processing_duration
```

#### Solutions

**Increase Processing Capacity**

```ini
[general]
worker_threads = 12  # Increase thread count
max_queue_size = 200000  # Increase queue size

[log_sources]
batch_size = 5000  # Increase batch size
```

**Implement Backpressure**

```ini
[performance]
enable_backpressure = true
backpressure_threshold = 50000
```

## Alert System Problems

### Problem: Alerts Not Being Sent

#### Symptoms

- No alerts received despite anomalies
- Alert generation metrics show alerts created
- Email/webhook failures

#### Diagnostic Steps

```bash
# Check alert metrics
curl -s http://localhost:8080/metrics | grep -E "alerts_(generated|delivered|failed)"

# Test SMTP connectivity
telnet mail.company.com 587

# Test webhook endpoint
curl -X POST https://hooks.company.com/anomaly-alerts -d '{"test": "message"}'
```

#### Solutions

**Fix SMTP Configuration**

```bash
# Test SMTP credentials
echo "Test email" | mail -s "Test Subject" -r "alerts@company.com" test@company.com

# Check SMTP logs
tail -f /var/log/mail.log
```

**Fix Webhook Configuration**

```ini
[alert_dispatchers]
webhook_enabled = true
webhook_url = "https://hooks.company.com/anomaly-alerts"
webhook_timeout = 30  # Increase timeout
webhook_retry_attempts = 3
```

### Problem: Too Many False Positive Alerts

#### Symptoms

- Alert volume very high
- Many alerts for normal activity
- Alert fatigue

#### Solutions

**Adjust Alert Thresholds**

```ini
[dynamic_learning]
# Enable learning to reduce false positives
enabled = true
learning_rate = 0.1
confidence_threshold = 0.8

[rule_engine]
# Increase alert thresholds
tier1_threshold = 10  # Increase from 5
tier2_threshold = 15  # Increase from 10
```

**Enable Alert Suppression**

```ini
[alerts]
enable_suppression = true
suppression_window = 3600  # 1 hour
max_similar_alerts = 5
```

## Prometheus Integration Issues

### Problem: Metrics Not Available

#### Symptoms

- `/metrics` endpoint returns 404 or empty
- Prometheus cannot scrape metrics
- Grafana dashboards show no data

#### Diagnostic Steps

```bash
# Test metrics endpoint
curl -v http://localhost:8080/metrics

# Check Prometheus configuration
grep -A 10 "anomaly-detector" /etc/prometheus/prometheus.yml

# Test Prometheus scraping
curl "http://prometheus:9090/api/v1/targets" | jq '.data.activeTargets[] | select(.job=="anomaly-detector")'
```

#### Solutions

**Fix Metrics Export**

```ini
[prometheus]
enabled = true
port = 8080
endpoint = "/metrics"
include_help_text = true
```

**Fix Prometheus Configuration**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: "anomaly-detector"
    static_configs:
      - targets: ["anomaly-detector:8080"] # Use correct hostname
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Problem: Tier 4 Queries Failing

#### Symptoms

- Tier 4 alerts not generated
- Prometheus query errors in logs
- High Tier 4 failure rate

#### Diagnostic Steps

```bash
# Test Prometheus connectivity
curl "http://prometheus:9090/api/v1/query?query=up"

# Check Tier 4 metrics
curl -s http://localhost:8080/metrics | grep tier4

# Test PromQL queries manually
curl "http://prometheus:9090/api/v1/query?query=rate(http_requests_total[5m])"
```

#### Solutions

**Fix Prometheus Connection**

```ini
[prometheus]
server_url = "http://prometheus:9090"  # Correct URL
timeout = 60  # Increase timeout
retry_attempts = 5
```

**Validate PromQL Queries**

```bash
# Test queries in Prometheus UI
# Navigate to http://prometheus:9090/graph
# Test each query individually
```

## Network and Connectivity Problems

### Problem: Cannot Connect to External Services

#### Symptoms

- Webhook alerts fail
- Prometheus queries fail
- DNS resolution errors

#### Diagnostic Steps

```bash
# Test DNS resolution
nslookup prometheus.company.com
dig @8.8.8.8 prometheus.company.com

# Test network connectivity
ping prometheus.company.com
telnet prometheus.company.com 9090

# Check firewall rules
sudo iptables -L OUTPUT -n
sudo ufw status
```

#### Solutions

**Fix DNS Issues**

```bash
# Add to /etc/hosts if needed
echo "10.0.1.100 prometheus.company.com" | sudo tee -a /etc/hosts

# Update DNS servers
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

**Fix Firewall Rules**

```bash
# Allow outbound HTTPS
sudo ufw allow out 443/tcp

# Allow Prometheus queries
sudo ufw allow out 9090/tcp
```

### Problem: High Network Latency

#### Symptoms

- Slow Prometheus queries
- Webhook timeouts
- High processing latency

#### Diagnostic Steps

```bash
# Measure network latency
ping -c 10 prometheus.company.com
traceroute prometheus.company.com

# Check network metrics
curl -s http://localhost:8080/metrics | grep network
```

#### Solutions

**Optimize Network Configuration**

```ini
[prometheus]
timeout = 120  # Increase timeout
connection_pool_size = 10
keep_alive = true

[alert_dispatchers]
webhook_timeout = 60  # Increase webhook timeout
```

## Advanced Debugging

### Enable Debug Logging

```ini
[general]
log_level = "DEBUG"
debug_enabled = true

[debug]
log_performance = true
log_memory_stats = true
log_rule_evaluation = true
```

### Performance Profiling

```bash
# CPU profiling
sudo perf record -g /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini
sudo perf report

# Memory profiling with Valgrind
valgrind --tool=massif /usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini

# Generate memory usage graph
ms_print massif.out.* > memory-profile.txt
```

### Core Dump Analysis

```bash
# Enable core dumps
sudo systemctl edit anomaly-detector
# Add:
# [Service]
# LimitCORE=infinity

# Analyze core dump
gdb /usr/local/bin/anomaly_detector core.12345
(gdb) bt
(gdb) info registers
(gdb) list
```

### Debugging Production Issues

```bash
# Attach debugger to running process
sudo gdb -p $(pgrep anomaly_detector)
(gdb) bt
(gdb) info threads
(gdb) thread apply all bt

# Generate diagnostic report
sudo tee /tmp/diagnostic-report.sh << 'EOF'
#!/bin/bash
echo "=== Anomaly Detector Diagnostic Report ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime)"
echo ""

echo "=== Service Status ==="
systemctl status anomaly-detector

echo "=== Resource Usage ==="
top -bn1 -p $(pgrep anomaly_detector) | tail -n +8

echo "=== Memory Info ==="
cat /proc/$(pgrep anomaly_detector)/status | grep -E "(VmSize|VmRSS|VmData)"

echo "=== Network Connections ==="
netstat -tuln | grep -E "(8080|9090)"

echo "=== Recent Logs ==="
journalctl -u anomaly-detector --since "1 hour ago" --no-pager | tail -50

echo "=== Metrics Sample ==="
timeout 10 curl -s http://localhost:8080/metrics | head -20

echo "=== Configuration ==="
head -50 /etc/anomaly-detector/config.ini
EOF

chmod +x /tmp/diagnostic-report.sh
sudo /tmp/diagnostic-report.sh > diagnostic-report-$(date +%Y%m%d_%H%M%S).txt
```

This troubleshooting guide provides comprehensive solutions for the most common operational issues. Keep this guide accessible for operations teams and update it based on real-world experiences.
