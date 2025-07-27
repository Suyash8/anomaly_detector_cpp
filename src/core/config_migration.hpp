#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Config {

// Configuration migration result
struct MigrationResult {
  bool success = false;
  std::string output_file;
  std::vector<std::string> warnings;
  std::vector<std::string> errors;
  std::vector<std::string> changes_made;
  int version_from = 0;
  int version_to = 0;
};

// Configuration version detector
class ConfigVersionDetector {
public:
  static int detect_version(const std::string &config_file);
  static bool has_section(const std::string &config_file,
                          const std::string &section);
  static std::vector<std::string> get_sections(const std::string &config_file);

private:
  static std::map<std::string, int> version_markers_;
};

// Configuration migrator for upgrading old configurations
class ConfigMigrator {
public:
  ConfigMigrator();

  // Main migration function
  MigrationResult migrate_config(const std::string &input_file,
                                 const std::string &output_file = "",
                                 bool backup_original = true);

  // Version-specific migration functions
  MigrationResult migrate_v1_to_v2(const std::string &input_file,
                                   const std::string &output_file);
  MigrationResult migrate_v2_to_v3(const std::string &input_file,
                                   const std::string &output_file);
  MigrationResult migrate_v3_to_current(const std::string &input_file,
                                        const std::string &output_file);

  // Utility functions
  void set_backup_directory(const std::string &backup_dir);
  void set_verbose_output(bool verbose);

  // Configuration templates
  void add_missing_sections(const std::string &config_file);
  void add_performance_monitoring_section(const std::string &config_file);
  void add_error_handling_section(const std::string &config_file);
  void add_memory_management_section(const std::string &config_file);

private:
  std::string backup_directory_;
  bool verbose_output_;

  // Helper functions
  std::string create_backup(const std::string &original_file);
  bool copy_file(const std::string &source, const std::string &dest);
  std::string generate_output_filename(const std::string &input_file);
  void log_migration_step(const std::string &message, MigrationResult &result);
  void add_default_section(const std::string &config_file,
                           const std::string &section,
                           const std::map<std::string, std::string> &defaults);
};

// Configuration validator for runtime validation
class ConfigValidator {
public:
  struct ValidationResult {
    bool is_valid = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::vector<std::string> suggestions;
  };

  // Runtime validation
  static ValidationResult validate_at_runtime(const AppConfig &config);
  static ValidationResult validate_file(const std::string &config_file);

  // Specific validation functions
  static ValidationResult
  validate_database_connectivity(const MongoLogSourceConfig &config);
  static ValidationResult
  validate_prometheus_connectivity(const PrometheusConfig &config);
  static ValidationResult validate_file_permissions(const AppConfig &config);
  static ValidationResult validate_network_ports(const AppConfig &config);
  static ValidationResult validate_memory_limits(const AppConfig &config);

  // Configuration health check
  static ValidationResult health_check(const AppConfig &config);

  // Performance validation
  static ValidationResult
  validate_performance_settings(const PerformanceMonitoringConfig &config,
                                const MemoryManagementConfig &memory_config);
};

// Hot reload manager for runtime configuration updates
class ConfigHotReloader {
public:
  ConfigHotReloader(std::shared_ptr<ConfigManager> config_manager);
  ~ConfigHotReloader();

  // Hot reload functionality
  void start_watching(const std::string &config_file);
  void stop_watching();
  bool is_watching() const;

  // Manual reload
  bool reload_config();

  // Callback registration for component updates
  using ReloadCallback = std::function<bool(const AppConfig &new_config,
                                            const AppConfig &old_config)>;
  void register_reload_callback(const std::string &component_name,
                                ReloadCallback callback);
  void unregister_reload_callback(const std::string &component_name);

  // Configuration change notifications
  void enable_change_notifications(bool enabled);

private:
  std::shared_ptr<ConfigManager> config_manager_;
  std::string watched_file_;
  std::atomic<bool> is_watching_;
  std::thread watcher_thread_;
  std::time_t last_modified_;

  std::map<std::string, ReloadCallback> reload_callbacks_;
  std::mutex callbacks_mutex_;
  bool notifications_enabled_;

  void watch_loop();
  bool file_changed();
  void notify_components(const AppConfig &new_config,
                         const AppConfig &old_config);
};

// Configuration template generator
class ConfigTemplateGenerator {
public:
  enum class DeploymentType {
    DEVELOPMENT,
    TESTING,
    STAGING,
    PRODUCTION,
    HIGH_PERFORMANCE,
    SECURITY_FOCUSED,
    MINIMAL
  };

  // Template generation
  static std::string generate_template(DeploymentType type);
  static bool save_template(DeploymentType type,
                            const std::string &output_file);

  // Customization
  static std::string
  customize_template(const std::string &base_template,
                     const std::map<std::string, std::string> &overrides);

  // Template validation
  static ValidationResult
  validate_template(const std::string &template_content);

  // Available templates
  static std::vector<std::string> get_available_templates();
  static std::string get_template_description(DeploymentType type);

private:
  static std::string get_development_template();
  static std::string get_testing_template();
  static std::string get_staging_template();
  static std::string get_production_template();
  static std::string get_high_performance_template();
  static std::string get_security_focused_template();
  static std::string get_minimal_template();
};

} // namespace Config
