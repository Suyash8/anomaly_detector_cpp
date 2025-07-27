# Grafana Dashboard Setup Guide

This guide provides instructions for setting up and customizing the Anomaly Detector Grafana dashboards for monitoring and visualization.

## Dashboard Overview

The monitoring system includes three specialized dashboards:

1. **System Overview** (`system-overview.json`) - Comprehensive system health and performance
2. **Security Analysis** (`security-analysis.json`) - Security threats and attack analysis
3. **Performance Analysis** (`performance-analysis.json`) - Detailed performance optimization metrics

## Prerequisites

### Required Components

- Grafana 7.5+ or later
- Prometheus data source configured
- Anomaly Detector running with metrics export enabled
- Alert Manager configured (optional, for alerting)

### Prometheus Configuration

Ensure Prometheus is configured to scrape the Anomaly Detector metrics endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: "anomaly-detector"
    static_configs:
      - targets: ["localhost:8080"] # Adjust host:port as needed
    scrape_interval: 15s
    metrics_path: "/metrics"
```

## Dashboard Installation

### Method 1: Grafana UI Import

1. Open Grafana web interface
2. Navigate to **+ (Create) → Import**
3. Upload the JSON file or paste the content
4. Configure data source (select your Prometheus instance)
5. Customize dashboard settings as needed
6. Click **Import**

### Method 2: Grafana API Import

```bash
# Import system overview dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @monitoring/grafana/dashboards/system-overview.json

# Import security analysis dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @monitoring/grafana/dashboards/security-analysis.json

# Import performance analysis dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @monitoring/grafana/dashboards/performance-analysis.json
```

### Method 3: Grafana Provisioning

Create a provisioning configuration file:

```yaml
# /etc/grafana/provisioning/dashboards/anomaly-detector.yml
apiVersion: 1

providers:
  - name: "anomaly-detector"
    orgId: 1
    folder: "Anomaly Detector"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards/anomaly-detector
```

Copy dashboard files to the provisioning directory:

```bash
sudo mkdir -p /var/lib/grafana/dashboards/anomaly-detector
sudo cp monitoring/grafana/dashboards/*.json /var/lib/grafana/dashboards/anomaly-detector/
sudo chown -R grafana:grafana /var/lib/grafana/dashboards/
```

## Data Source Configuration

### Prometheus Data Source Setup

1. Navigate to **Configuration → Data Sources**
2. Click **Add data source**
3. Select **Prometheus**
4. Configure connection settings:
   - **URL**: `http://localhost:9090` (adjust as needed)
   - **Access**: Server (default)
   - **Scrape interval**: 15s
   - **Query timeout**: 60s
5. Click **Save & Test**

### Advanced Configuration

For high-availability setups, configure multiple Prometheus instances:

```json
{
  "name": "Prometheus-HA",
  "type": "prometheus",
  "url": "http://prometheus-1:9090,http://prometheus-2:9090",
  "access": "proxy",
  "jsonData": {
    "httpMethod": "POST",
    "timeInterval": "15s"
  }
}
```

## Dashboard Customization

### Template Variables

Each dashboard includes template variables for filtering:

- **Instance**: Filter by specific Anomaly Detector instances
- **Severity**: Filter alerts by severity level (Security dashboard)
- **Time Range**: Adjust analysis time window

### Custom Queries

Common PromQL patterns for extending dashboards:

```promql
# Custom metrics by component
sum by (component) (rate(anomaly_detector_alerts_generated_total[5m]))

# Top error sources
topk(5, sum by (error_type) (rate(anomaly_detector_processing_errors_total[1h])))

# Memory growth rate
deriv(anomaly_detector_memory_allocated_bytes[1h])

# Processing efficiency
(
  sum(rate(anomaly_detector_logs_processed_total[5m])) /
  sum(rate(anomaly_detector_log_processing_duration_ms_sum[5m]))
) * 1000
```

### Panel Configuration

#### Adding Custom Panels

1. Click **Add Panel** on dashboard
2. Select visualization type
3. Configure query using PromQL
4. Set display options (colors, thresholds, units)
5. Add panel title and description

#### Threshold Configuration

For operational alerts, configure panel thresholds:

```json
{
  "thresholds": {
    "mode": "absolute",
    "steps": [
      { "color": "green", "value": null },
      { "color": "yellow", "value": 70 },
      { "color": "red", "value": 90 }
    ]
  }
}
```

## Alert Integration

### Grafana Alerting

Configure alerts directly in Grafana panels:

1. Edit panel
2. Navigate to **Alert** tab
3. Create alert rule with conditions
4. Configure notification channels
5. Set alert frequency and evaluation

### Prometheus Alert Manager

Import the provided alert rules:

```bash
# Copy alert rules to Prometheus
sudo cp monitoring/grafana/alerts/anomaly-detector-alerts.yml /etc/prometheus/rules/

# Update prometheus.yml
rule_files:
  - "rules/anomaly-detector-alerts.yml"

# Reload Prometheus configuration
sudo systemctl reload prometheus
```

## Dashboard Maintenance

### Regular Updates

- **Weekly**: Review dashboard performance and adjust queries
- **Monthly**: Update thresholds based on baseline changes
- **Quarterly**: Evaluate new metrics and panels

### Performance Optimization

#### Query Optimization

```promql
# Use recording rules for expensive queries
# prometheus-rules.yml
groups:
  - name: anomaly_detector_recordings
    rules:
      - record: anomaly_detector:processing_rate_5m
        expr: sum(rate(anomaly_detector_logs_processed_total[5m]))

      - record: anomaly_detector:error_rate_5m
        expr: sum(rate(anomaly_detector_processing_errors_total[5m])) / sum(rate(anomaly_detector_logs_processed_total[5m]))
```

#### Dashboard Settings

- Set appropriate refresh intervals (30s-5m depending on urgency)
- Use relative time ranges when possible
- Limit the number of series in time series panels
- Configure query timeout values appropriately

## Troubleshooting

### Common Issues

#### No Data Displayed

1. Verify Prometheus data source connectivity
2. Check metric names in queries match exported metrics
3. Ensure time range includes data
4. Verify Anomaly Detector is exporting metrics

#### Slow Dashboard Performance

1. Optimize PromQL queries using recording rules
2. Reduce time range for complex queries
3. Use appropriate step intervals
4. Consider data source query parallelization

#### Missing Metrics

1. Check Anomaly Detector configuration for metrics export
2. Verify Prometheus scraping configuration
3. Check for metric name changes in application updates
4. Ensure proper labeling in queries

### Debug Commands

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify metric availability
curl http://localhost:9090/api/v1/label/__name__/values | grep anomaly_detector

# Test specific queries
curl -G http://localhost:9090/api/v1/query \
  --data-urlencode 'query=up{job="anomaly-detector"}'
```

## Security Considerations

### Dashboard Access Control

Configure appropriate permissions:

```json
{
  "dashboard": {
    "permissions": [
      { "role": "Viewer", "permission": 1 },
      { "role": "Editor", "permission": 2 },
      { "team": "Security", "permission": 2 },
      { "team": "Operations", "permission": 4 }
    ]
  }
}
```

### Data Source Security

- Use authentication for Prometheus access
- Configure TLS encryption for data source connections
- Implement network-level access controls
- Regular security audits of dashboard configurations

## Advanced Features

### Annotations

Configure automatic annotations for events:

```json
{
  "annotations": {
    "builtIn": 1,
    "datasource": "Prometheus",
    "enable": true,
    "expr": "changes(anomaly_detector_config_reloads_total[5m]) > 0",
    "iconColor": "rgba(0, 211, 255, 1)",
    "name": "Config Reloads",
    "step": "1m"
  }
}
```

### Custom Variables

Create dynamic variables for dashboard customization:

```json
{
  "name": "severity_threshold",
  "type": "custom",
  "options": [
    { "text": "Low", "value": "1" },
    { "text": "Medium", "value": "2" },
    { "text": "High", "value": "3" },
    { "text": "Critical", "value": "4" }
  ]
}
```

### Export and Sharing

#### Dashboard Export

```bash
# Export dashboard via API
curl -X GET \
  'http://admin:admin@localhost:3000/api/dashboards/uid/anomaly-detector-overview' \
  -H 'Content-Type: application/json' > dashboard-backup.json
```

#### Sharing Options

- **Snapshot**: Create static snapshots for incident analysis
- **Export**: JSON export for version control
- **Embedding**: Embed panels in external applications
- **Public Dashboard**: Share with external stakeholders (with caution)

## Version Control

### Dashboard Versioning

Maintain dashboard versions in Git:

```bash
git add monitoring/grafana/dashboards/
git commit -m "feat(monitoring): update dashboard thresholds for improved detection"
git tag dashboard-v1.2.0
```

### Change Management

- Document all dashboard modifications
- Test changes in staging environment
- Coordinate updates with team deployments
- Maintain rollback procedures

This comprehensive setup guide ensures proper deployment and maintenance of the Anomaly Detector monitoring infrastructure.
