#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <sys/stat.h>
#include <vector>

// Simple configuration migration tool
class SimpleConfigMigrator {
public:
  struct MigrationResult {
    bool success = false;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::vector<std::string> changes;
  };

  static MigrationResult migrate_config(const std::string &input_file) {
    MigrationResult result;

    if (!file_exists(input_file)) {
      result.errors.push_back("Configuration file does not exist: " +
                              input_file);
      return result;
    }

    int version = detect_version(input_file);
    std::cout << "Detected configuration version: " << version << std::endl;

    if (version >= 3) {
      result.success = true;
      result.warnings.push_back("Configuration is already up to date");
      return result;
    }

    // Create backup
    std::string backup_file = create_backup(input_file);
    if (!backup_file.empty()) {
      result.changes.push_back("Created backup: " + backup_file);
      std::cout << "Created backup: " << backup_file << std::endl;
    }

    // Add missing sections
    if (version < 2) {
      if (!has_section(input_file, "MemoryManagement")) {
        add_memory_management_section(input_file);
        result.changes.push_back("Added MemoryManagement section");
      }
      if (!has_section(input_file, "PrometheusConfig")) {
        add_prometheus_section(input_file);
        result.changes.push_back("Added PrometheusConfig section");
      }
    }

    if (version < 3) {
      if (!has_section(input_file, "PerformanceMonitoring")) {
        add_performance_monitoring_section(input_file);
        result.changes.push_back("Added PerformanceMonitoring section");
      }
      if (!has_section(input_file, "ErrorHandling")) {
        add_error_handling_section(input_file);
        result.changes.push_back("Added ErrorHandling section");
      }
      update_version_number(input_file, 3);
      result.changes.push_back("Updated version to 3");
    }

    result.success = true;
    return result;
  }

private:
  static bool file_exists(const std::string &filepath) {
    struct stat buffer;
    return (stat(filepath.c_str(), &buffer) == 0);
  }

  static int detect_version(const std::string &config_file) {
    std::ifstream file(config_file);
    if (!file.is_open())
      return 0;

    std::string line;
    int version = 1;

    while (std::getline(file, line)) {
      if (line.find("[PerformanceMonitoring]") != std::string::npos ||
          line.find("[ErrorHandling]") != std::string::npos) {
        version = 3;
      } else if (line.find("[MemoryManagement]") != std::string::npos ||
                 line.find("[PrometheusConfig]") != std::string::npos) {
        version = std::max(version, 2);
      } else if (line.find("version") == 0) {
        size_t eq_pos = line.find('=');
        if (eq_pos != std::string::npos) {
          std::string version_str = line.substr(eq_pos + 1);
          // Remove whitespace
          version_str.erase(0, version_str.find_first_not_of(" \t"));
          version_str.erase(version_str.find_last_not_of(" \t") + 1);
          try {
            version = std::max(version, std::stoi(version_str));
          } catch (...) {
          }
        }
      }
    }

    return version;
  }

  static bool has_section(const std::string &config_file,
                          const std::string &section) {
    std::ifstream file(config_file);
    if (!file.is_open())
      return false;

    std::string line;
    std::string target = "[" + section + "]";

    while (std::getline(file, line)) {
      if (line.find(target) != std::string::npos) {
        return true;
      }
    }

    return false;
  }

  static std::string create_backup(const std::string &original_file) {
    std::time_t now = std::time(nullptr);
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S",
                  std::localtime(&now));

    size_t last_dot = original_file.find_last_of('.');
    std::string base_name = (last_dot != std::string::npos)
                                ? original_file.substr(0, last_dot)
                                : original_file;
    std::string extension =
        (last_dot != std::string::npos) ? original_file.substr(last_dot) : "";

    std::string backup_file =
        base_name + "_backup_" + std::string(timestamp) + extension;

    std::ifstream src(original_file, std::ios::binary);
    std::ofstream dst(backup_file, std::ios::binary);

    if (src.is_open() && dst.is_open()) {
      dst << src.rdbuf();
      return backup_file;
    }

    return "";
  }

  static void add_memory_management_section(const std::string &config_file) {
    std::ofstream file(config_file, std::ios::app);
    if (file.is_open()) {
      file << "\n[MemoryManagement]\n";
      file << "max_memory_usage = 2048\n";
      file << "gc_threshold = 85\n";
      file << "buffer_size = 8192\n";
      file << "enable_memory_pooling = true\n";
      file << "pool_initial_size = 1024\n";
      file << "pool_max_size = 4096\n";
      file << "monitoring_enabled = true\n\n";
    }
  }

  static void add_prometheus_section(const std::string &config_file) {
    std::ofstream file(config_file, std::ios::app);
    if (file.is_open()) {
      file << "\n[PrometheusConfig]\n";
      file << "enabled = true\n";
      file << "host = localhost\n";
      file << "port = 9090\n";
      file << "metrics_port = 8080\n";
      file << "push_interval = 10\n";
      file << "job_name = anomaly_detector\n\n";
    }
  }

  static void
  add_performance_monitoring_section(const std::string &config_file) {
    std::ofstream file(config_file, std::ios::app);
    if (file.is_open()) {
      file << "\n[PerformanceMonitoring]\n";
      file << "enabled = true\n";
      file << "collection_interval = 5\n";
      file << "cpu_threshold = 80.0\n";
      file << "memory_threshold = 85.0\n";
      file << "disk_threshold = 90.0\n";
      file << "network_threshold = 75.0\n";
      file << "alert_on_threshold_breach = true\n";
      file << "performance_log_level = INFO\n\n";
    }
  }

  static void add_error_handling_section(const std::string &config_file) {
    std::ofstream file(config_file, std::ios::app);
    if (file.is_open()) {
      file << "\n[ErrorHandling]\n";
      file << "strategy = RETRY_WITH_BACKOFF\n";
      file << "max_retries = 3\n";
      file << "retry_delay = 1000\n";
      file << "backoff_multiplier = 2.0\n";
      file << "circuit_breaker_enabled = true\n";
      file << "circuit_breaker_threshold = 5\n";
      file << "circuit_breaker_timeout = 30000\n";
      file << "fallback_enabled = true\n\n";
    }
  }

  static void update_version_number(const std::string &config_file,
                                    int new_version) {
    std::ifstream input(config_file);
    std::string content;
    std::string line;
    bool version_found = false;

    while (std::getline(input, line)) {
      if (line.find("version") == 0 && line.find("=") != std::string::npos) {
        content += "version = " + std::to_string(new_version) + "\n";
        version_found = true;
      } else {
        content += line + "\n";
      }
    }
    input.close();

    if (!version_found) {
      content += "\n# Configuration version\n";
      content += "version = " + std::to_string(new_version) + "\n";
    }

    std::ofstream output(config_file);
    output << content;
    output.close();
  }
};

int main(int argc, char *argv[]) {
  std::cout << "Anomaly Detector Configuration Migration Tool\n";
  std::cout << "============================================\n\n";

  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <config_file>\n";
    std::cout << "Example: " << argv[0] << " config.ini\n";
    return 1;
  }

  std::string config_file = argv[1];
  std::cout << "Migrating configuration file: " << config_file << "\n\n";

  auto result = SimpleConfigMigrator::migrate_config(config_file);

  if (result.success) {
    std::cout << "✓ Migration completed successfully!\n\n";

    if (!result.changes.empty()) {
      std::cout << "Changes made:\n";
      for (const auto &change : result.changes) {
        std::cout << "  - " << change << "\n";
      }
      std::cout << "\n";
    }

    if (!result.warnings.empty()) {
      std::cout << "Warnings:\n";
      for (const auto &warning : result.warnings) {
        std::cout << "  ! " << warning << "\n";
      }
      std::cout << "\n";
    }

    std::cout << "Your configuration has been updated to version 3.\n";
    std::cout << "Please review the new settings and adjust as needed.\n";

    return 0;
  } else {
    std::cout << "✗ Migration failed!\n\n";

    if (!result.errors.empty()) {
      std::cout << "Errors:\n";
      for (const auto &error : result.errors) {
        std::cout << "  ✗ " << error << "\n";
      }
    }

    return 1;
  }
}
