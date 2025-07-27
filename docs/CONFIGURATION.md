# Configuration System Documentation

## Overview

The Anomaly Detector uses a comprehensive configuration system that supports hot-reloading, validation, and automatic migration between versions. This document explains how to use and maintain configuration files.

## Configuration File Structure

Configuration files use INI format with sections and key-value pairs:

```ini
# Main application settings
[Application]
name = AnomalyDetector
version = 3
log_level = INFO

# Database connection settings
[MongoLogSource]
host = localhost
port = 27017
database = logs
collection = events

# Performance monitoring configuration
[PerformanceMonitoring]
enabled = true
collection_interval = 5
cpu_threshold = 80.0
memory_threshold = 85.0
disk_threshold = 90.0
network_threshold = 75.0
alert_on_threshold_breach = true
performance_log_level = INFO

# Error handling configuration
[ErrorHandling]
strategy = RETRY_WITH_BACKOFF
max_retries = 3
retry_delay = 1000
backoff_multiplier = 2.0
circuit_breaker_enabled = true
circuit_breaker_threshold = 5
circuit_breaker_timeout = 30000
fallback_enabled = true

# Memory management settings
[MemoryManagement]
max_memory_usage = 2048
gc_threshold = 85
buffer_size = 8192
enable_memory_pooling = true
pool_initial_size = 1024
pool_max_size = 4096
monitoring_enabled = true

# Prometheus metrics configuration
[PrometheusConfig]
enabled = true
host = localhost
port = 9090
metrics_port = 8080
push_interval = 10
job_name = anomaly_detector
```

## Configuration Versions

The configuration system supports versioning to ensure compatibility:

- **Version 1**: Basic configuration with core settings
- **Version 2**: Added MemoryManagement and PrometheusConfig sections
- **Version 3**: Added PerformanceMonitoring and ErrorHandling sections (current)

## Configuration Templates

Several deployment-specific templates are available:

### Development Configuration (`config_templates/development.ini`)

- Enhanced debugging and logging
- Lower performance thresholds for testing
- More verbose error reporting
- Reduced retry attempts for faster feedback

### Production Configuration (`config_templates/production.ini`)

- Optimized for stability and security
- Conservative performance thresholds
- Comprehensive error handling
- Security-focused settings

### High-Performance Configuration (`config_templates/high_performance.ini`)

- Optimized for processing 10,000+ logs per second
- Maximum memory allocation
- Aggressive performance thresholds
- Minimal logging overhead

## Configuration Migration

### Automatic Migration

Use the configuration migration tool to upgrade old configuration files:

```bash
# Build the migration tool
cmake --build build --target config_migrator

# Migrate a configuration file
./build/config_migrator config.ini
```

The tool will:

1. Detect the current configuration version
2. Create a backup of the original file
3. Add missing sections with default values
4. Update the version number
5. Report all changes made

### Manual Migration

If you prefer manual migration:

1. **Check current version**: Look for the `version` key in your configuration
2. **Add missing sections**: Compare with the latest example configuration
3. **Update version number**: Set `version = 3` in your configuration

## Configuration Validation

The system validates configuration at startup and runtime:

### Startup Validation

- File existence and readability
- Required sections and keys
- Value ranges and formats
- Network connectivity (optional)

### Runtime Validation

- Memory usage monitoring
- Network port availability
- Database connectivity
- File permissions

### Validation Errors

Common validation errors and solutions:

```
Error: MongoDB host cannot be empty
Solution: Set host = localhost or your MongoDB server address

Error: Port conflict: 8080
Solution: Use different ports for different services

Warning: Very high memory limit: 16384MB
Solution: Consider reducing max_memory_usage for better stability
```

## Hot Configuration Reload

The system supports hot-reloading of configuration changes without restart:

### Enabling Hot Reload

```cpp
// In your application code
auto config_manager = std::make_shared<ConfigManager>();
ConfigHotReloader hot_reloader(config_manager);

// Start watching for changes
hot_reloader.start_watching("config.ini");

// Register callback for component updates
hot_reloader.register_reload_callback("performance_monitor",
    [](const AppConfig& new_config, const AppConfig& old_config) {
        // Update component with new configuration
        return true; // Return true if update successful
    });
```

### Hot Reload Behavior

- Configuration file is monitored for changes
- Changes are validated before applying
- Components are notified in order of registration
- Failed updates can be rolled back

## Configuration Best Practices

### Security

1. **File Permissions**: Set configuration files to read-only for the application user
2. **Sensitive Data**: Use environment variables for passwords and secrets
3. **Backup Strategy**: Keep configuration backups in version control
4. **Access Control**: Limit who can modify production configurations

### Performance

1. **Memory Limits**: Set appropriate memory limits based on available RAM
2. **Thresholds**: Tune alert thresholds based on your environment
3. **Polling Intervals**: Balance monitoring frequency with performance impact
4. **Connection Pools**: Configure database connection pooling appropriately

### Maintenance

1. **Version Control**: Track configuration changes in git
2. **Documentation**: Document custom settings and their purposes
3. **Testing**: Test configuration changes in development first
4. **Monitoring**: Monitor configuration validation errors

## Environment-Specific Settings

### Development Environment

```ini
[Application]
log_level = DEBUG
development_mode = true

[PerformanceMonitoring]
collection_interval = 1  # More frequent monitoring
cpu_threshold = 90.0     # Higher thresholds for dev machines
```

### Production Environment

```ini
[Application]
log_level = INFO
development_mode = false

[PerformanceMonitoring]
collection_interval = 5  # Standard monitoring
cpu_threshold = 80.0     # Conservative thresholds
```

### High-Load Environment

```ini
[MemoryManagement]
max_memory_usage = 8192  # Increased memory
buffer_size = 16384      # Larger buffers

[PerformanceMonitoring]
collection_interval = 10 # Less frequent monitoring overhead
```

## Troubleshooting

### Configuration Not Loading

1. Check file path and permissions
2. Verify INI format syntax
3. Check for missing required sections
4. Review application logs for parsing errors

### Hot Reload Not Working

1. Verify file system supports modification notifications
2. Check file permissions for the configuration file
3. Ensure the configuration file path is absolute
4. Review hot reload callback implementations

### Performance Issues

1. Reduce monitoring frequency
2. Increase buffer sizes
3. Adjust memory allocation settings
4. Review log level settings

### Validation Failures

1. Check network connectivity
2. Verify port availability
3. Confirm database accessibility
4. Review file system permissions

## Configuration Schema Reference

### Required Sections

- `[Application]`: Basic application settings
- `[MongoLogSource]`: Database connection configuration

### Optional Sections

- `[PerformanceMonitoring]`: System performance monitoring
- `[ErrorHandling]`: Error handling and retry logic
- `[MemoryManagement]`: Memory allocation and pooling
- `[PrometheusConfig]`: Metrics collection and export

### Key Value Types

- **String**: Text values (e.g., `host = localhost`)
- **Integer**: Whole numbers (e.g., `port = 27017`)
- **Float**: Decimal numbers (e.g., `threshold = 80.5`)
- **Boolean**: true/false values (e.g., `enabled = true`)

## Migration Examples

### Version 1 to 2 Migration

```bash
# Before migration (v1)
[Application]
name = AnomalyDetector
log_level = INFO

# After migration (v2) - sections added automatically
[Application]
name = AnomalyDetector
log_level = INFO

[MemoryManagement]
max_memory_usage = 2048
# ... other memory settings

[PrometheusConfig]
enabled = true
# ... other prometheus settings
```

### Version 2 to 3 Migration

```bash
# Additional sections added in v3
[PerformanceMonitoring]
enabled = true
# ... performance monitoring settings

[ErrorHandling]
strategy = RETRY_WITH_BACKOFF
# ... error handling settings
```

For more information, see the example configuration files in the `config_templates/` directory.
