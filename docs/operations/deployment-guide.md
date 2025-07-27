# Deployment Guide

This comprehensive guide covers the deployment of the Anomaly Detector system in production environments, including system requirements, setup procedures, and initial configuration.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Configuration Setup](#configuration-setup)
4. [Service Configuration](#service-configuration)
5. [Monitoring Setup](#monitoring-setup)
6. [Security Hardening](#security-hardening)
7. [Validation and Testing](#validation-and-testing)
8. [Maintenance Setup](#maintenance-setup)

## System Requirements

### Hardware Requirements

#### Minimum Requirements

- **CPU**: 4 cores (2.0 GHz or higher)
- **Memory**: 8 GB RAM
- **Storage**: 50 GB available disk space
- **Network**: 1 Gbps network interface

#### Recommended Production Requirements

- **CPU**: 8+ cores (2.5 GHz or higher)
- **Memory**: 16+ GB RAM
- **Storage**: 100+ GB SSD storage
- **Network**: 10 Gbps network interface for high-volume environments

#### High-Volume Production Requirements

- **CPU**: 16+ cores (3.0 GHz or higher)
- **Memory**: 32+ GB RAM
- **Storage**: 500+ GB NVMe SSD
- **Network**: 10+ Gbps network interface
- **Additional**: Consider NUMA topology optimization

### Software Requirements

#### Operating System

- **Primary**: Ubuntu 20.04 LTS or later
- **Alternative**: CentOS 8/RHEL 8 or later
- **Container**: Docker 20.10+ or Podman 3.0+

#### System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libcurl4-openssl-dev \
    pkg-config \
    ca-certificates

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y \
    cmake \
    git \
    openssl-devel \
    libcurl-devel \
    pkgconfig \
    ca-certificates
```

#### Runtime Dependencies

- **C++ Runtime**: libstdc++.so.6 (GCC 9+ compatible)
- **SSL/TLS**: OpenSSL 1.1.1 or later
- **HTTP Client**: libcurl 7.68+ with SSL support
- **System Libraries**: pthread, dl, rt

### Network Requirements

#### Inbound Connections

- **Metrics Endpoint**: Port 8080 (configurable)
- **Health Check**: Port 8080/health (same as metrics)
- **Log Input**: Configurable (file monitoring, syslog, API)

#### Outbound Connections

- **Prometheus Server**: Port 9090 (for Tier 4 queries)
- **Alert Destinations**: Variable (email SMTP, webhooks, etc.)
- **External APIs**: HTTPS (443) for threat intelligence feeds

#### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 8080/tcp comment "Anomaly Detector Metrics"
sudo ufw allow out 9090/tcp comment "Prometheus Queries"
sudo ufw allow out 443/tcp comment "HTTPS Outbound"

# iptables
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 9090 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
```

## Installation Methods

### Method 1: Binary Installation (Recommended)

#### Download and Install

```bash
# Create application directory
sudo mkdir -p /opt/anomaly-detector
cd /opt/anomaly-detector

# Download latest release
wget https://github.com/your-org/anomaly-detector/releases/latest/download/anomaly-detector-linux-x86_64.tar.gz

# Extract and install
sudo tar -xzf anomaly-detector-linux-x86_64.tar.gz
sudo chmod +x anomaly_detector

# Create symbolic link for system PATH
sudo ln -sf /opt/anomaly-detector/anomaly_detector /usr/local/bin/anomaly_detector
```

#### Verify Installation

```bash
anomaly_detector --version
anomaly_detector --help
```

### Method 2: Docker Deployment

#### Pull and Run Container

```bash
# Pull latest image
docker pull your-registry/anomaly-detector:latest

# Create data and config directories
sudo mkdir -p /opt/anomaly-detector/{config,data,logs}

# Run container
docker run -d \
  --name anomaly-detector \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /opt/anomaly-detector/config:/app/config:ro \
  -v /opt/anomaly-detector/data:/app/data \
  -v /opt/anomaly-detector/logs:/app/logs \
  -v /var/log:/var/log:ro \
  your-registry/anomaly-detector:latest
```

#### Docker Compose Deployment

```yaml
# docker-compose.yml
version: "3.8"

services:
  anomaly-detector:
    image: your-registry/anomaly-detector:latest
    container_name: anomaly-detector
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
      - /var/log:/var/log:ro
    environment:
      - AD_CONFIG_PATH=/app/config/config.ini
      - AD_LOG_LEVEL=INFO
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
```

### Method 3: Source Compilation

#### Prerequisites Setup

```bash
# Install vcpkg for dependency management
git clone https://github.com/Microsoft/vcpkg.git /opt/vcpkg
cd /opt/vcpkg
./bootstrap-vcpkg.sh
export VCPKG_ROOT=/opt/vcpkg
export PATH=$VCPKG_ROOT:$PATH
```

#### Build Process

```bash
# Clone repository
git clone https://github.com/your-org/anomaly-detector.git
cd anomaly-detector

# Build dependencies
./build.sh --deps-only

# Build application
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
make -j$(nproc)

# Install
sudo make install
```

## Configuration Setup

### Initial Configuration

#### Create Configuration Directory

```bash
sudo mkdir -p /etc/anomaly-detector
sudo mkdir -p /var/lib/anomaly-detector
sudo mkdir -p /var/log/anomaly-detector
```

#### Copy Configuration Templates

```bash
# Copy base configuration
sudo cp config_templates/production.ini /etc/anomaly-detector/config.ini

# Set proper permissions
sudo chown -R anomaly-detector:anomaly-detector /etc/anomaly-detector
sudo chown -R anomaly-detector:anomaly-detector /var/lib/anomaly-detector
sudo chown -R anomaly-detector:anomaly-detector /var/log/anomaly-detector

sudo chmod 640 /etc/anomaly-detector/config.ini
sudo chmod 750 /var/lib/anomaly-detector
sudo chmod 750 /var/log/anomaly-detector
```

### Core Configuration

#### Basic System Configuration

```ini
[general]
# Application settings
app_name = "Anomaly Detector Production"
log_level = "INFO"
worker_threads = 8
max_queue_size = 100000

# Data directories
data_directory = "/var/lib/anomaly-detector"
log_directory = "/var/log/anomaly-detector"

[log_sources]
# Log input configuration
enabled = true
file_paths = ["/var/log/nginx/access.log", "/var/log/apache2/access.log"]
follow_mode = true
batch_size = 1000
```

#### Prometheus Integration

```ini
[prometheus]
# Metrics export
enabled = true
port = 8080
endpoint = "/metrics"
collection_interval = 15

# Tier 4 queries
query_enabled = true
server_url = "http://prometheus:9090"
timeout = 30
retry_attempts = 3
```

#### Memory Management

```ini
[memory_management]
# Memory limits
max_memory_mb = 4096
pool_size_mb = 512
eviction_threshold = 0.85
cleanup_interval = 300

# Object pooling
enable_pooling = true
pool_sizes = {
    "LogEntry": 10000,
    "AnalyzedEvent": 5000,
    "PerIPState": 1000
}
```

### Security Configuration

#### Alert Configuration

```ini
[alerts]
# Alert settings
enabled = true
throttle_window = 300
max_alerts_per_window = 100

[alert_dispatchers]
# Email alerts
email_enabled = true
smtp_server = "mail.company.com"
smtp_port = 587
smtp_username = "alerts@company.com"
smtp_password = "env:SMTP_PASSWORD"
recipients = ["security@company.com", "ops@company.com"]

# Webhook alerts
webhook_enabled = true
webhook_url = "https://hooks.company.com/anomaly-alerts"
webhook_timeout = 10
```

### Environment Variables

#### Required Environment Variables

```bash
# Create environment file
sudo tee /etc/anomaly-detector/environment << EOF
# Database credentials (if applicable)
AD_DB_PASSWORD=secure_password_here

# SMTP credentials
AD_SMTP_PASSWORD=smtp_password_here

# API keys
AD_THREAT_INTEL_API_KEY=api_key_here

# TLS certificates
AD_TLS_CERT_PATH=/etc/ssl/certs/anomaly-detector.crt
AD_TLS_KEY_PATH=/etc/ssl/private/anomaly-detector.key
EOF

sudo chmod 600 /etc/anomaly-detector/environment
sudo chown anomaly-detector:anomaly-detector /etc/anomaly-detector/environment
```

## Service Configuration

### SystemD Service Setup

#### Create Service User

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /var/lib/anomaly-detector --create-home anomaly-detector

# Add to necessary groups
sudo usermod -a -G adm anomaly-detector  # For log file access
```

#### Service Definition

```bash
# Create service file
sudo tee /etc/systemd/system/anomaly-detector.service << EOF
[Unit]
Description=Anomaly Detector Service
Documentation=https://docs.company.com/anomaly-detector
After=network.target
Wants=network.target

[Service]
Type=notify
User=anomaly-detector
Group=anomaly-detector

# Service execution
ExecStart=/usr/local/bin/anomaly_detector --config /etc/anomaly-detector/config.ini
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

# Environment
Environment=AD_CONFIG_PATH=/etc/anomaly-detector/config.ini
EnvironmentFile=/etc/anomaly-detector/environment

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/anomaly-detector /var/log/anomaly-detector
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Restart policy
Restart=always
RestartSec=10
StartLimitBurst=3
StartLimitIntervalSec=60

[Install]
WantedBy=multi-user.target
EOF
```

#### Enable and Start Service

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable anomaly-detector

# Start service
sudo systemctl start anomaly-detector

# Check service status
sudo systemctl status anomaly-detector
```

### Log Rotation Setup

#### Configure Logrotate

```bash
sudo tee /etc/logrotate.d/anomaly-detector << EOF
/var/log/anomaly-detector/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 anomaly-detector anomaly-detector
    postrotate
        /bin/kill -HUP \$(cat /var/run/anomaly-detector.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
```

## Monitoring Setup

### Prometheus Configuration

#### Add Scrape Target

```yaml
# Add to prometheus.yml
scrape_configs:
  - job_name: "anomaly-detector"
    static_configs:
      - targets: ["localhost:8080"]
    scrape_interval: 15s
    metrics_path: "/metrics"
    timeout: 10s
```

### Health Checks

#### Load Balancer Health Check

```bash
# Health check endpoint test
curl -f http://localhost:8080/health

# Expected response: 200 OK
# {"status": "healthy", "timestamp": "2025-07-27T10:00:00Z"}
```

#### Comprehensive Health Validation

```bash
#!/bin/bash
# health-check.sh

set -e

# Configuration
SERVICE_URL="http://localhost:8080"
TIMEOUT=10

# Check service health
echo "Checking service health..."
curl -s -f --max-time $TIMEOUT "$SERVICE_URL/health" | jq .

# Check metrics endpoint
echo "Checking metrics endpoint..."
curl -s -f --max-time $TIMEOUT "$SERVICE_URL/metrics" | head -10

# Check service status
echo "Checking service status..."
systemctl is-active anomaly-detector

echo "Health check completed successfully!"
```

## Security Hardening

### File Permissions

#### Secure Configuration Files

```bash
# Set restrictive permissions
sudo chmod 640 /etc/anomaly-detector/config.ini
sudo chmod 600 /etc/anomaly-detector/environment

# Verify permissions
sudo find /etc/anomaly-detector -type f -exec ls -la {} \;
```

### Network Security

#### TLS Configuration

```ini
[network]
# TLS settings
tls_enabled = true
tls_cert_file = "/etc/ssl/certs/anomaly-detector.crt"
tls_key_file = "/etc/ssl/private/anomaly-detector.key"
tls_min_version = "1.2"
```

#### Rate Limiting

```ini
[security]
# Rate limiting
enable_rate_limiting = true
max_requests_per_minute = 1000
burst_size = 100
block_duration = 300
```

## Validation and Testing

### Post-Deployment Testing

#### Functional Testing

```bash
#!/bin/bash
# deployment-test.sh

echo "Starting post-deployment validation..."

# Test 1: Service is running
if systemctl is-active --quiet anomaly-detector; then
    echo "✓ Service is running"
else
    echo "✗ Service is not running"
    exit 1
fi

# Test 2: Health endpoint responds
if curl -s -f http://localhost:8080/health > /dev/null; then
    echo "✓ Health endpoint accessible"
else
    echo "✗ Health endpoint not accessible"
    exit 1
fi

# Test 3: Metrics are being exported
if curl -s http://localhost:8080/metrics | grep -q "anomaly_detector"; then
    echo "✓ Metrics are being exported"
else
    echo "✗ Metrics export not working"
    exit 1
fi

# Test 4: Log processing is working
LOG_COUNT=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')
sleep 30
NEW_LOG_COUNT=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')

if (( $(echo "$NEW_LOG_COUNT > $LOG_COUNT" | bc -l) )); then
    echo "✓ Log processing is active"
else
    echo "! Log processing may be idle (no new logs)"
fi

echo "Deployment validation completed!"
```

### Performance Validation

#### Load Testing

```bash
#!/bin/bash
# load-test.sh

echo "Starting load test..."

# Generate test logs
for i in {1..10000}; do
    echo "$(date '+%d/%b/%Y:%H:%M:%S %z') \"GET /api/test HTTP/1.1\" 200 1234 192.168.1.$((RANDOM % 254 + 1))" >> /tmp/test.log
done

# Copy to monitored location
sudo cp /tmp/test.log /var/log/test/access.log

# Monitor processing
echo "Monitoring processing for 60 seconds..."
start_count=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')
sleep 60
end_count=$(curl -s http://localhost:8080/metrics | grep "anomaly_detector_logs_processed_total" | awk '{print $2}')

processed=$((end_count - start_count))
echo "Processed $processed logs in 60 seconds"
echo "Processing rate: $((processed / 60)) logs/second"

# Cleanup
sudo rm -f /var/log/test/access.log /tmp/test.log
```

## Maintenance Setup

### Backup Configuration

#### Configuration Backup Script

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/opt/backups/anomaly-detector"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
    /etc/anomaly-detector/ \
    /var/lib/anomaly-detector/

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "config_*.tar.gz" -mtime +30 -delete

echo "Configuration backup completed: $BACKUP_DIR/config_$DATE.tar.gz"
```

### Update Procedures

#### Safe Update Process

```bash
#!/bin/bash
# update-service.sh

set -e

echo "Starting safe update process..."

# Backup current version
sudo systemctl stop anomaly-detector
sudo cp /usr/local/bin/anomaly_detector /usr/local/bin/anomaly_detector.backup

# Install new version
sudo cp new_anomaly_detector /usr/local/bin/anomaly_detector
sudo chmod +x /usr/local/bin/anomaly_detector

# Test new version
if /usr/local/bin/anomaly_detector --version; then
    echo "✓ New version validated"
else
    echo "✗ New version failed validation, rolling back"
    sudo cp /usr/local/bin/anomaly_detector.backup /usr/local/bin/anomaly_detector
    exit 1
fi

# Start service with new version
sudo systemctl start anomaly-detector

# Verify service starts correctly
sleep 10
if systemctl is-active --quiet anomaly-detector; then
    echo "✓ Service started successfully with new version"
    sudo rm /usr/local/bin/anomaly_detector.backup
else
    echo "✗ Service failed to start, rolling back"
    sudo systemctl stop anomaly-detector
    sudo cp /usr/local/bin/anomaly_detector.backup /usr/local/bin/anomaly_detector
    sudo systemctl start anomaly-detector
    exit 1
fi

echo "Update completed successfully!"
```

This deployment guide provides a comprehensive foundation for production deployment of the Anomaly Detector system with proper security, monitoring, and maintenance procedures.
