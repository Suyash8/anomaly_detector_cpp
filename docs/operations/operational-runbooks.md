# Operational Runbooks

This document provides step-by-step procedures for common operational tasks and maintenance activities for the Anomaly Detector system.

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Weekly Maintenance](#weekly-maintenance)
3. [Monthly Tasks](#monthly-tasks)
4. [Emergency Procedures](#emergency-procedures)
5. [System Updates](#system-updates)
6. [Configuration Management](#configuration-management)
7. [Performance Optimization](#performance-optimization)
8. [Backup and Recovery](#backup-and-recovery)
9. [Monitoring and Alerting](#monitoring-and-alerting)
10. [Troubleshooting Procedures](#troubleshooting-procedures)

## Daily Operations

### Morning Health Check

**Purpose**: Verify system health and performance after overnight operations.

**Frequency**: Daily at start of business hours

**Duration**: 5-10 minutes

**Prerequisites**: Access to monitoring dashboard and command line

#### Procedure

**Step 1: Service Status Verification**

```bash
# Check service status
systemctl status anomaly-detector

# Expected output: active (running)
# If not running, follow "Service Recovery" procedure
```

**Step 2: Health Endpoint Check**

```bash
# Test health endpoint
curl -f http://localhost:8080/health

# Expected response: {"status": "healthy", "timestamp": "..."}
# If unhealthy, investigate logs immediately
```

**Step 3: Processing Metrics Review**

```bash
# Check processing rate
curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total"

# Check for processing in last 5 minutes
CURRENT_COUNT=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')
sleep 60
NEW_COUNT=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')

if [ "$NEW_COUNT" -gt "$CURRENT_COUNT" ]; then
    echo "✓ Processing is active"
else
    echo "⚠ Processing may be stalled - investigate"
fi
```

**Step 4: Resource Utilization Check**

```bash
# Check CPU and memory usage
curl -s http://localhost:8080/metrics | grep -E "(cpu_usage|memory_usage)"

# Alert thresholds:
# CPU > 80% = Investigation required
# Memory > 85% = Investigation required
```

**Step 5: Alert Status Review**

```bash
# Check recent alerts
curl -s http://localhost:8080/metrics | grep "anomaly_detector_alerts_generated_total"

# Review alert delivery status
curl -s http://localhost:8080/metrics | grep -E "(alerts_delivered|alerts_failed)"
```

**Step 6: Log Review**

```bash
# Check for errors in last 24 hours
sudo journalctl -u anomaly-detector --since "24 hours ago" -p err

# If errors found, review and escalate if necessary
```

#### Escalation Criteria

- Service not running
- Health endpoint returns unhealthy
- CPU usage > 90% for extended period
- Memory usage > 95%
- No log processing activity for > 30 minutes
- Error rate > 5%

### Log Processing Verification

**Purpose**: Ensure logs are being processed correctly and efficiently.

**Frequency**: Multiple times daily

**Duration**: 2-3 minutes

#### Procedure

**Step 1: Queue Depth Check**

```bash
# Check queue sizes
curl -s http://localhost:8080/metrics | grep "queue_size"

# Alert if:
# input_queue_size > 50,000
# processing_queue_size > 10,000
# alert_queue_size > 5,000
```

**Step 2: Processing Latency Check**

```bash
# Check processing latency percentiles
curl -s http://localhost:8080/metrics | grep "processing_duration" | grep "quantile"

# Alert if P95 > 1000ms or P99 > 5000ms
```

**Step 3: Error Rate Monitoring**

```bash
# Calculate error rate
ERRORS=$(curl -s http://localhost:8080/metrics | grep "processing_errors_total" | awk '{print $2}')
PROCESSED=$(curl -s http://localhost:8080/metrics | grep "logs_processed_total" | awk '{print $2}')
ERROR_RATE=$(echo "scale=4; $ERRORS / $PROCESSED * 100" | bc)

echo "Current error rate: ${ERROR_RATE}%"

# Alert if error rate > 1%
```

## Weekly Maintenance

### System Performance Review

**Purpose**: Analyze system performance trends and identify optimization opportunities.

**Frequency**: Weekly, preferably during low-traffic periods

**Duration**: 30-45 minutes

#### Procedure

**Step 1: Performance Metrics Analysis**

```bash
#!/bin/bash
# weekly-performance-review.sh

REPORT_DATE=$(date +%Y-%m-%d)
REPORT_FILE="performance-report-$REPORT_DATE.txt"

echo "=== Weekly Performance Report - $REPORT_DATE ===" > "$REPORT_FILE"

# Processing rate trends
echo "Processing Rate Trends:" >> "$REPORT_FILE"
curl -s "http://prometheus:9090/api/v1/query_range?query=rate(anomaly_detector_logs_processed_total[5m])&start=$(date -d '7 days ago' +%s)&end=$(date +%s)&step=3600" | jq '.data.result[0].values' >> "$REPORT_FILE"

# Memory usage trends
echo "Memory Usage Trends:" >> "$REPORT_FILE"
curl -s "http://prometheus:9090/api/v1/query_range?query=anomaly_detector_memory_usage_percent&start=$(date -d '7 days ago' +%s)&end=$(date +%s)&step=3600" | jq '.data.result[0].values' >> "$REPORT_FILE"

# Alert volume analysis
echo "Alert Volume Analysis:" >> "$REPORT_FILE"
curl -s "http://prometheus:9090/api/v1/query_range?query=increase(anomaly_detector_alerts_generated_total[1h])&start=$(date -d '7 days ago' +%s)&end=$(date +%s)&step=3600" | jq '.data.result[0].values' >> "$REPORT_FILE"

echo "Performance report generated: $REPORT_FILE"
```

**Step 2: Capacity Planning Assessment**

```bash
# Check if approaching capacity limits
CURRENT_RATE=$(curl -s http://localhost:8080/metrics | grep "processing_rate" | awk '{print $2}')
MAX_CAPACITY=10000  # logs/second

CAPACITY_USAGE=$(echo "scale=2; $CURRENT_RATE / $MAX_CAPACITY * 100" | bc)
echo "Current capacity usage: ${CAPACITY_USAGE}%"

# Alert if > 70% capacity
if (( $(echo "$CAPACITY_USAGE > 70" | bc -l) )); then
    echo "WARNING: Approaching capacity limits"
fi
```

**Step 3: Log Storage Analysis**

```bash
# Check log storage usage
LOG_DIR="/var/log/anomaly-detector"
TOTAL_SIZE=$(du -sh "$LOG_DIR" | cut -f1)
echo "Total log storage used: $TOTAL_SIZE"

# Check for log growth trends
find "$LOG_DIR" -name "*.log" -mtime -7 -exec ls -lh {} \; | awk '{sum+=$5} END {print "Last 7 days growth: " sum/1024/1024 " MB"}'
```

### Configuration Backup and Validation

**Purpose**: Ensure configuration is backed up and validate current settings.

**Frequency**: Weekly

**Duration**: 15-20 minutes

#### Procedure

**Step 1: Configuration Backup**

```bash
#!/bin/bash
# config-backup.sh

BACKUP_DIR="/opt/backups/anomaly-detector/weekly"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup configuration files
tar -czf "$BACKUP_DIR/config-backup-$DATE.tar.gz" \
    /etc/anomaly-detector/ \
    /var/lib/anomaly-detector/baselines/ \
    /var/lib/anomaly-detector/statistics/

# Backup system service configuration
cp /etc/systemd/system/anomaly-detector.service "$BACKUP_DIR/service-$DATE.conf"

# Generate configuration checksum
sha256sum /etc/anomaly-detector/config.ini > "$BACKUP_DIR/config-checksum-$DATE.txt"

echo "Configuration backup completed: $BACKUP_DIR"
```

**Step 2: Configuration Validation**

```bash
# Validate current configuration
anomaly_detector --config /etc/anomaly-detector/config.ini --validate-config

if [ $? -eq 0 ]; then
    echo "✓ Configuration validation passed"
else
    echo "✗ Configuration validation failed - investigate"
fi
```

**Step 3: Configuration Drift Detection**

```bash
# Compare with baseline configuration
diff -u /opt/baselines/config.ini /etc/anomaly-detector/config.ini

# If differences found, document and approve changes
```

## Monthly Tasks

### Security Review and Updates

**Purpose**: Review security posture and apply necessary updates.

**Frequency**: Monthly

**Duration**: 2-3 hours

#### Procedure

**Step 1: Security Audit**

```bash
#!/bin/bash
# monthly-security-audit.sh

echo "=== Monthly Security Audit ==="

# Check for security updates
apt list --upgradable | grep -i security

# Review user accounts
echo "System users with shell access:"
getent passwd | grep -E '/bin/(bash|sh|zsh)$'

# Check file permissions
echo "Checking critical file permissions:"
ls -la /etc/anomaly-detector/
ls -la /usr/local/bin/anomaly_detector

# Review active network connections
echo "Active network connections:"
netstat -tuln | grep LISTEN

# Check for SUID/SGID files
echo "SUID/SGID files in application directories:"
find /usr/local/bin /opt/anomaly-detector -perm /6000 -type f 2>/dev/null

echo "Security audit completed"
```

**Step 2: Certificate Renewal Check**

```bash
# Check certificate expiration
CERT_FILE="/etc/ssl/certs/anomaly-detector.crt"
openssl x509 -enddate -noout -in "$CERT_FILE"

# Calculate days until expiration
expiry_date=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
expiry_timestamp=$(date -d "$expiry_date" +%s)
current_timestamp=$(date +%s)
days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))

echo "Certificate expires in $days_until_expiry days"

# Renew if < 30 days
if [ $days_until_expiry -lt 30 ]; then
    echo "Certificate renewal required"
    # Follow certificate renewal procedure
fi
```

**Step 3: Access Review**

```bash
# Review system access logs
echo "Recent authentication events:"
sudo journalctl _COMM=sshd --since "30 days ago" | grep -E "(Accepted|Failed)"

# Review application access
echo "API access patterns:"
grep -E "(GET|POST)" /var/log/anomaly-detector/access.log | tail -100
```

### Database Maintenance (if applicable)

**Purpose**: Perform database optimization and cleanup.

**Frequency**: Monthly

**Duration**: 1-2 hours

#### Procedure

**Step 1: Data Cleanup**

```bash
# Clean up old data based on retention policies
anomaly_detector --config /etc/anomaly-detector/config.ini --cleanup-old-data

# Verify cleanup results
echo "Data cleanup completed. Current storage usage:"
du -sh /var/lib/anomaly-detector/
```

**Step 2: Statistics Optimization**

```bash
# Optimize statistical models
anomaly_detector --config /etc/anomaly-detector/config.ini --optimize-models

# Verify model health
curl -s http://localhost:8080/metrics | grep "learning_model_health"
```

## Emergency Procedures

### Service Recovery

**Purpose**: Restore service operation after failure.

**Trigger**: Service down alert or health check failure

**Duration**: 5-30 minutes depending on issue

#### Procedure

**Step 1: Immediate Assessment**

```bash
# Check service status
systemctl status anomaly-detector

# Check for obvious issues
journalctl -u anomaly-detector --since "10 minutes ago" -p err

# Check system resources
free -h
df -h
```

**Step 2: Quick Recovery Attempt**

```bash
# Attempt service restart
sudo systemctl restart anomaly-detector

# Wait for startup
sleep 30

# Verify recovery
curl -f http://localhost:8080/health

if [ $? -eq 0 ]; then
    echo "✓ Service recovered successfully"
    # Follow up with root cause analysis
else
    echo "✗ Service restart failed - escalate immediately"
fi
```

**Step 3: Escalation Path**
If quick recovery fails:

1. Check system logs for critical errors
2. Contact on-call engineer
3. Consider rollback to previous version
4. Activate disaster recovery if necessary

### Memory Exhaustion Recovery

**Purpose**: Recover from out-of-memory conditions.

**Trigger**: Memory usage > 95% or OOM killer activation

#### Procedure

**Step 1: Emergency Memory Cleanup**

```bash
# Check memory usage
free -h

# Force garbage collection (if supported)
kill -USR1 $(pgrep anomaly_detector)

# Check if memory freed
sleep 30
free -h
```

**Step 2: Temporary Relief**

```bash
# Reduce processing load temporarily
# Enable backpressure mode
curl -X POST http://localhost:8080/admin/enable-backpressure

# Or reduce worker threads
curl -X POST http://localhost:8080/admin/set-workers -d '{"count": 4}'
```

**Step 3: Permanent Fix**

```bash
# Adjust memory configuration
sudo vim /etc/anomaly-detector/config.ini
# Reduce max_memory_mb and pool sizes

# Restart with new configuration
sudo systemctl restart anomaly-detector
```

### High CPU Usage Mitigation

**Purpose**: Reduce CPU load when approaching critical levels.

**Trigger**: CPU usage > 90% for extended period

#### Procedure

**Step 1: Identify CPU Hotspots**

```bash
# Check CPU usage breakdown
top -p $(pgrep anomaly_detector) -H

# Profile CPU usage
sudo perf top -p $(pgrep anomaly_detector)
```

**Step 2: Temporary Load Reduction**

```bash
# Disable expensive operations temporarily
curl -X POST http://localhost:8080/admin/disable-tier4
curl -X POST http://localhost:8080/admin/reduce-learning-rate

# Increase batch sizes to reduce overhead
curl -X POST http://localhost:8080/admin/set-batch-size -d '{"size": 5000}'
```

**Step 3: Monitor Recovery**

```bash
# Monitor CPU usage
watch -n 5 'curl -s http://localhost:8080/metrics | grep cpu_usage'

# Re-enable features gradually once CPU normalizes
```

## System Updates

### Application Update Procedure

**Purpose**: Safely update the Anomaly Detector application.

**Frequency**: As needed for security patches or feature updates

**Duration**: 30-60 minutes

#### Procedure

**Step 1: Pre-Update Preparation**

```bash
#!/bin/bash
# pre-update-checklist.sh

echo "=== Pre-Update Checklist ==="

# Backup current configuration
./config-backup.sh

# Backup current binary
sudo cp /usr/local/bin/anomaly_detector /usr/local/bin/anomaly_detector.backup-$(date +%Y%m%d)

# Check current version
/usr/local/bin/anomaly_detector --version

# Test current configuration
anomaly_detector --config /etc/anomaly-detector/config.ini --validate-config

# Document current metrics
curl -s http://localhost:8080/metrics > pre-update-metrics.txt

echo "Pre-update preparation completed"
```

**Step 2: Update Installation**

```bash
#!/bin/bash
# install-update.sh

NEW_VERSION_FILE="$1"

if [ ! -f "$NEW_VERSION_FILE" ]; then
    echo "Usage: $0 <new-binary-file>"
    exit 1
fi

# Validate new binary
if ! file "$NEW_VERSION_FILE" | grep -q "executable"; then
    echo "Error: File is not a valid executable"
    exit 1
fi

# Stop service
sudo systemctl stop anomaly-detector

# Install new version
sudo cp "$NEW_VERSION_FILE" /usr/local/bin/anomaly_detector
sudo chmod +x /usr/local/bin/anomaly_detector

# Start service
sudo systemctl start anomaly-detector

# Wait for startup
sleep 30

# Verify startup
if systemctl is-active --quiet anomaly-detector; then
    echo "✓ Update successful"
else
    echo "✗ Update failed - rolling back"
    sudo systemctl stop anomaly-detector
    sudo cp /usr/local/bin/anomaly_detector.backup-$(date +%Y%m%d) /usr/local/bin/anomaly_detector
    sudo systemctl start anomaly-detector
    exit 1
fi
```

**Step 3: Post-Update Validation**

```bash
#!/bin/bash
# post-update-validation.sh

echo "=== Post-Update Validation ==="

# Check version
echo "New version:"
/usr/local/bin/anomaly_detector --version

# Verify health
curl -f http://localhost:8080/health

# Check processing after 5 minutes
sleep 300
NEW_COUNT=$(curl -s http://localhost:8080/metrics | grep "logs_processed_total" | awk '{print $2}')
echo "Processing count after update: $NEW_COUNT"

# Compare metrics
echo "Comparing metrics..."
curl -s http://localhost:8080/metrics > post-update-metrics.txt
diff pre-update-metrics.txt post-update-metrics.txt

echo "Post-update validation completed"
```

### Configuration Update Procedure

**Purpose**: Safely update configuration settings.

**Duration**: 10-15 minutes

#### Procedure

**Step 1: Configuration Preparation**

```bash
# Validate new configuration
anomaly_detector --config new-config.ini --validate-config

if [ $? -ne 0 ]; then
    echo "Configuration validation failed"
    exit 1
fi

# Backup current configuration
cp /etc/anomaly-detector/config.ini /etc/anomaly-detector/config.ini.backup-$(date +%Y%m%d_%H%M%S)
```

**Step 2: Configuration Deployment**

```bash
# Deploy new configuration
sudo cp new-config.ini /etc/anomaly-detector/config.ini
sudo chown root:anomaly-detector /etc/anomaly-detector/config.ini
sudo chmod 640 /etc/anomaly-detector/config.ini

# Reload configuration (if supported)
kill -HUP $(pgrep anomaly_detector)

# Or restart service
sudo systemctl restart anomaly-detector
```

**Step 3: Configuration Verification**

```bash
# Verify service starts with new configuration
sleep 30
systemctl is-active --quiet anomaly-detector

# Test functionality
curl -f http://localhost:8080/health

# Monitor for 10 minutes for any issues
for i in {1..10}; do
    sleep 60
    echo "Minute $i: $(curl -s http://localhost:8080/health)"
done
```

## Backup and Recovery

### Daily Backup Procedure

**Purpose**: Create daily backups of critical data and configuration.

**Frequency**: Daily at 2 AM

**Duration**: 15-30 minutes

#### Procedure

**Step 1: Automated Backup Script**

```bash
#!/bin/bash
# daily-backup.sh

BACKUP_ROOT="/opt/backups/anomaly-detector"
DATE=$(date +%Y%m%d)
BACKUP_DIR="$BACKUP_ROOT/daily/$DATE"

mkdir -p "$BACKUP_DIR"

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_DIR/config.tar.gz" /etc/anomaly-detector/

# Backup application data
echo "Backing up application data..."
tar -czf "$BACKUP_DIR/data.tar.gz" /var/lib/anomaly-detector/

# Backup logs (last 7 days)
echo "Backing up recent logs..."
find /var/log/anomaly-detector -name "*.log" -mtime -7 -exec tar -czf "$BACKUP_DIR/logs.tar.gz" {} \;

# Generate backup manifest
echo "Creating backup manifest..."
cat > "$BACKUP_DIR/manifest.txt" << EOF
Backup Date: $(date)
Hostname: $(hostname)
Application Version: $(/usr/local/bin/anomaly_detector --version)
Files Backed Up:
$(ls -la "$BACKUP_DIR")
EOF

# Verify backup integrity
echo "Verifying backup integrity..."
for file in "$BACKUP_DIR"/*.tar.gz; do
    if tar -tzf "$file" > /dev/null 2>&1; then
        echo "✓ $file - OK"
    else
        echo "✗ $file - CORRUPTED"
    fi
done

# Cleanup old backups (keep 30 days)
find "$BACKUP_ROOT/daily" -maxdepth 1 -type d -mtime +30 -exec rm -rf {} \;

echo "Daily backup completed: $BACKUP_DIR"
```

### Recovery Procedure

**Purpose**: Restore system from backup in case of data loss or corruption.

**Trigger**: Data corruption, hardware failure, or disaster recovery

#### Procedure

**Step 1: Assessment and Preparation**

```bash
# Assess the extent of data loss
echo "Assessing system state..."

# Check what data is available
ls -la /etc/anomaly-detector/
ls -la /var/lib/anomaly-detector/
ls -la /var/log/anomaly-detector/

# Identify latest backup
LATEST_BACKUP=$(find /opt/backups/anomaly-detector/daily -maxdepth 1 -type d | sort | tail -1)
echo "Latest backup: $LATEST_BACKUP"
```

**Step 2: System Recovery**

```bash
#!/bin/bash
# system-recovery.sh

BACKUP_DIR="$1"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    exit 1
fi

echo "Starting system recovery from $BACKUP_DIR"

# Stop service
sudo systemctl stop anomaly-detector

# Restore configuration
echo "Restoring configuration..."
sudo tar -xzf "$BACKUP_DIR/config.tar.gz" -C /

# Restore data
echo "Restoring application data..."
sudo tar -xzf "$BACKUP_DIR/data.tar.gz" -C /

# Set proper permissions
sudo chown -R anomaly-detector:anomaly-detector /var/lib/anomaly-detector
sudo chown root:anomaly-detector /etc/anomaly-detector/config.ini
sudo chmod 640 /etc/anomaly-detector/config.ini

# Validate restored configuration
echo "Validating restored configuration..."
anomaly_detector --config /etc/anomaly-detector/config.ini --validate-config

if [ $? -eq 0 ]; then
    echo "✓ Configuration validation passed"
else
    echo "✗ Configuration validation failed"
    exit 1
fi

# Start service
sudo systemctl start anomaly-detector

# Verify recovery
sleep 30
if systemctl is-active --quiet anomaly-detector; then
    echo "✓ System recovery successful"
else
    echo "✗ System recovery failed"
    exit 1
fi

echo "Recovery completed successfully"
```

This comprehensive set of operational runbooks provides detailed procedures for all common maintenance tasks and emergency situations that operations teams may encounter.
