#include "config_migration.hpp"
#include "config.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

namespace Config {

// Helper function to trim strings
std::string trim(const std::string &str) {
  size_t first = str.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return "";
  size_t last = str.find_last_not_of(" \t\r\n");
  return str.substr(first, (last - first + 1));
}

// Helper function to check if file exists
bool file_exists(const std::string &filepath) {
  struct stat buffer;
  return (stat(filepath.c_str(), &buffer) == 0);
}

// ConfigVersionDetector implementation
std::map<std::string, int> ConfigVersionDetector::version_markers_ = {
    {"PerformanceMonitoring", 3},
    {"ErrorHandling", 3},
    {"MemoryManagement", 2},
    {"PrometheusConfig", 2},
    {"version", 1}};

int ConfigVersionDetector::detect_version(const std::string &config_file) {
  std::ifstream file(config_file);
  if (!file.is_open()) {
    return 0;
  }

  std::string line;
  int detected_version = 1;

  while (std::getline(file, line)) {
    line = trim(line);

    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    if (line[0] == '[' && line.back() == ']') {
      std::string section = line.substr(1, line.length() - 2);
      auto it = version_markers_.find(section);
      if (it != version_markers_.end()) {
        detected_version = std::max(detected_version, it->second);
      }
    }

    if (line.find("version") == 0) {
      size_t eq_pos = line.find('=');
      if (eq_pos != std::string::npos) {
        std::string version_str = line.substr(eq_pos + 1);
        version_str = trim(version_str);
        try {
          detected_version = std::max(detected_version, std::stoi(version_str));
        } catch (...) {
          // Ignore invalid version numbers
        }
      }
    }
  }

  return detected_version;
}

bool ConfigVersionDetector::has_section(const std::string &config_file,
                                        const std::string &section) {
  std::ifstream file(config_file);
  if (!file.is_open()) {
    return false;
  }

  std::string line;
  std::string target_section = "[" + section + "]";

  while (std::getline(file, line)) {
    line = trim(line);
    if (line == target_section) {
      return true;
    }
  }

  return false;
}

std::vector<std::string>
ConfigVersionDetector::get_sections(const std::string &config_file) {
  std::vector<std::string> sections;
  std::ifstream file(config_file);
  if (!file.is_open()) {
    return sections;
  }

  std::string line;
  while (std::getline(file, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    if (line[0] == '[' && line.back() == ']') {
      sections.push_back(line.substr(1, line.length() - 2));
    }
  }

  return sections;
}

// ConfigMigrator implementation
ConfigMigrator::ConfigMigrator()
    : backup_directory_("./config_backups"), verbose_output_(false) {
  // Create backup directory if it doesn't exist
  mkdir(backup_directory_.c_str(), 0755);
}

MigrationResult ConfigMigrator::migrate_config(const std::string &input_file,
                                               const std::string &output_file,
                                               bool backup_original) {
  MigrationResult result;

  if (!file_exists(input_file)) {
    result.errors.push_back("Input file does not exist: " + input_file);
    return result;
  }

  result.version_from = ConfigVersionDetector::detect_version(input_file);
  result.version_to = 3;

  if (result.version_from == result.version_to) {
    result.success = true;
    result.warnings.push_back("Configuration is already at the latest version");
    result.output_file = input_file;
    return result;
  }

  if (backup_original) {
    std::string backup_file = create_backup(input_file);
    if (backup_file.empty()) {
      result.errors.push_back("Failed to create backup of original file");
      return result;
    }
    result.changes_made.push_back("Created backup: " + backup_file);
  }

  result.output_file =
      output_file.empty() ? generate_output_filename(input_file) : output_file;

  if (!copy_file(input_file, result.output_file)) {
    result.errors.push_back("Failed to copy input file to output location");
    return result;
  }

  try {
    if (result.version_from == 1) {
      auto v2_result = migrate_v1_to_v2(result.output_file, result.output_file);
      result.warnings.insert(result.warnings.end(), v2_result.warnings.begin(),
                             v2_result.warnings.end());
      result.changes_made.insert(result.changes_made.end(),
                                 v2_result.changes_made.begin(),
                                 v2_result.changes_made.end());
      if (!v2_result.success) {
        result.errors.insert(result.errors.end(), v2_result.errors.begin(),
                             v2_result.errors.end());
        return result;
      }
    }

    if (result.version_from <= 2) {
      auto v3_result = migrate_v2_to_v3(result.output_file, result.output_file);
      result.warnings.insert(result.warnings.end(), v3_result.warnings.begin(),
                             v3_result.warnings.end());
      result.changes_made.insert(result.changes_made.end(),
                                 v3_result.changes_made.begin(),
                                 v3_result.changes_made.end());
      if (!v3_result.success) {
        result.errors.insert(result.errors.end(), v3_result.errors.begin(),
                             v3_result.errors.end());
        return result;
      }
    }

    result.success = true;
    log_migration_step("Migration completed successfully", result);

  } catch (const std::exception &e) {
    result.errors.push_back("Migration failed with exception: " +
                            std::string(e.what()));
  }

  return result;
}

MigrationResult
ConfigMigrator::migrate_v1_to_v2(const std::string &input_file,
                                 const std::string &output_file) {
  MigrationResult result;
  result.version_from = 1;
  result.version_to = 2;

  if (!ConfigVersionDetector::has_section(input_file, "MemoryManagement")) {
    add_memory_management_section(output_file);
    result.changes_made.push_back(
        "Added MemoryManagement section with default values");
  }

  if (!ConfigVersionDetector::has_section(input_file, "PrometheusConfig")) {
    std::map<std::string, std::string> prometheus_defaults = {
        {"enabled", "true"},     {"host", "localhost"},
        {"port", "9090"},        {"metrics_port", "8080"},
        {"push_interval", "10"}, {"job_name", "anomaly_detector"}};
    add_default_section(output_file, "PrometheusConfig", prometheus_defaults);
    result.changes_made.push_back(
        "Added PrometheusConfig section with default values");
  }

  result.success = true;
  return result;
}

MigrationResult
ConfigMigrator::migrate_v2_to_v3(const std::string &input_file,
                                 const std::string &output_file) {
  MigrationResult result;
  result.version_from = 2;
  result.version_to = 3;

  if (!ConfigVersionDetector::has_section(input_file,
                                          "PerformanceMonitoring")) {
    add_performance_monitoring_section(output_file);
    result.changes_made.push_back(
        "Added PerformanceMonitoring section with default values");
  }

  if (!ConfigVersionDetector::has_section(input_file, "ErrorHandling")) {
    add_error_handling_section(output_file);
    result.changes_made.push_back(
        "Added ErrorHandling section with default values");
  }

  std::ifstream input(output_file);
  std::ostringstream buffer;
  std::string line;
  bool version_found = false;

  while (std::getline(input, line)) {
    if (line.find("version") == 0 && line.find("=") != std::string::npos) {
      buffer << "version = 3
                ";
          version_found = true;
      result.changes_made.push_back("Updated version number to 3");
    } else {
      buffer << line
             << "
                ";
    }
  }
  input.close();

  if (!version_found) {
    buffer << "
#Configuration version
              ";
        buffer
           << "version = 3
              ";
              result.changes_made.push_back(
                  "Added version number (3) to configuration");
  }

  std::ofstream output(output_file);
  output << buffer.str();
  output.close();

  result.success = true;
  return result;
}

MigrationResult
ConfigMigrator::migrate_v3_to_current(const std::string & /*input_file*/,
                                      const std::string & /*output_file*/) {
  MigrationResult result;
  result.version_from = 3;
  result.version_to = 3;
  result.success = true;
  result.warnings.push_back("Configuration is already at the current version");
  return result;
}

void ConfigMigrator::add_performance_monitoring_section(
    const std::string &config_file) {
  std::map<std::string, std::string> defaults = {
      {"enabled", "true"},
      {"collection_interval", "5"},
      {"cpu_threshold", "80.0"},
      {"memory_threshold", "85.0"},
      {"disk_threshold", "90.0"},
      {"network_threshold", "75.0"},
      {"alert_on_threshold_breach", "true"},
      {"performance_log_level", "INFO"}};
  add_default_section(config_file, "PerformanceMonitoring", defaults);
}

void ConfigMigrator::add_error_handling_section(
    const std::string &config_file) {
  std::map<std::string, std::string> defaults = {
      {"strategy", "RETRY_WITH_BACKOFF"},
      {"max_retries", "3"},
      {"retry_delay", "1000"},
      {"backoff_multiplier", "2.0"},
      {"circuit_breaker_enabled", "true"},
      {"circuit_breaker_threshold", "5"},
      {"circuit_breaker_timeout", "30000"},
      {"fallback_enabled", "true"}};
  add_default_section(config_file, "ErrorHandling", defaults);
}

void ConfigMigrator::add_memory_management_section(
    const std::string &config_file) {
  std::map<std::string, std::string> defaults = {
      {"max_memory_usage", "2048"},  {"gc_threshold", "85"},
      {"buffer_size", "8192"},       {"enable_memory_pooling", "true"},
      {"pool_initial_size", "1024"}, {"pool_max_size", "4096"},
      {"monitoring_enabled", "true"}};
  add_default_section(config_file, "MemoryManagement", defaults);
}

std::string ConfigMigrator::create_backup(const std::string &original_file) {
  auto now = std::time(nullptr);
  std::ostringstream ss;
  ss << std::put_time(std::localtime(&now), "%Y%m%d_%H%M%S");

  size_t last_slash = original_file.find_last_of('/');
  size_t last_dot = original_file.find_last_of('.');

  std::string filename = (last_slash != std::string::npos)
                             ? original_file.substr(last_slash + 1)
                             : original_file;
  std::string base_name =
      (last_dot != std::string::npos) ? filename.substr(0, last_dot) : filename;
  std::string extension =
      (last_dot != std::string::npos) ? filename.substr(last_dot) : "";

  std::string backup_filename = base_name + "_backup_" + ss.str() + extension;
  std::string backup_path = backup_directory_ + "/" + backup_filename;

  if (copy_file(original_file, backup_path)) {
    return backup_path;
  }
  return "";
}

bool ConfigMigrator::copy_file(const std::string &source,
                               const std::string &dest) {
  std::ifstream src(source, std::ios::binary);
  std::ofstream dst(dest, std::ios::binary);

  if (!src.is_open() || !dst.is_open()) {
    return false;
  }

  dst << src.rdbuf();
  return true;
}

std::string
ConfigMigrator::generate_output_filename(const std::string &input_file) {
  size_t last_slash = input_file.find_last_of('/');
  size_t last_dot = input_file.find_last_of('.');

  std::string path = (last_slash != std::string::npos)
                         ? input_file.substr(0, last_slash + 1)
                         : "";
  std::string filename = (last_slash != std::string::npos)
                             ? input_file.substr(last_slash + 1)
                             : input_file;
  std::string base_name =
      (last_dot != std::string::npos) ? filename.substr(0, last_dot) : filename;
  std::string extension =
      (last_dot != std::string::npos) ? filename.substr(last_dot) : "";

  if (base_name.find("_migrated") == std::string::npos) {
    return path + base_name + "_migrated" + extension;
  }
  return input_file;
}

void ConfigMigrator::log_migration_step(const std::string &message,
                                        MigrationResult &result) {
  if (verbose_output_) {
    result.changes_made.push_back(message);
  }
}

void ConfigMigrator::add_default_section(
    const std::string &config_file, const std::string &section,
    const std::map<std::string, std::string> &defaults) {
  std::ofstream file(config_file, std::ios::app);
  if (!file.is_open()) {
    return;
  }

  file << "
              [" << section << "] ";
      for (const auto &pair : defaults){file << pair.first << " = "
                                             << pair.second
                                             << "
                                                ";
      } file
       << "
          ";
          file.close();
}

// Simplified ConfigValidator implementation
ConfigValidator::ValidationResult
ConfigValidator::validate_at_runtime(const AppConfig &config) {
  ValidationResult result;
  result.is_valid = true;
  return result; // Simplified for now
}

ConfigValidator::ValidationResult
ConfigValidator::validate_file(const std::string &config_file) {
  ValidationResult result;

  if (!file_exists(config_file)) {
    result.is_valid = false;
    result.errors.push_back("Configuration file does not exist: " +
                            config_file);
    return result;
  }

  result.is_valid = true;
  return result;
}

// Stub implementations for other validation methods
ConfigValidator::ValidationResult
ConfigValidator::validate_database_connectivity(
    const MongoLogSourceConfig & /*config*/) {
  ValidationResult result;
  result.is_valid = true;
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_prometheus_connectivity(
    const PrometheusConfig & /*config*/) {
  ValidationResult result;
  result.is_valid = true;
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_file_permissions(const AppConfig & /*config*/) {
  ValidationResult result;
  result.is_valid = true;
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_network_ports(const AppConfig & /*config*/) {
  ValidationResult result;
  result.is_valid = true;
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_memory_limits(const AppConfig & /*config*/) {
  ValidationResult result;
  result.is_valid = true;
  return result;
}

} // namespace Config

namespace Config {

// Helper function to trim strings
std::string trim(const std::string &str) {
  size_t first = str.find_first_not_of(' ');
  if (first == std::string::npos)
    return "";
  size_t last = str.find_last_not_of(' ');
  return str.substr(first, (last - first + 1));
}

// Helper function to check if file exists
bool file_exists(const std::string &filepath) {
  struct stat buffer;
  return (stat(filepath.c_str(), &buffer) == 0);
}

// Helper function to copy file
bool copy_file_content(const std::string &source, const std::string &dest) {
  std::ifstream src(source, std::ios::binary);
  std::ofstream dst(dest, std::ios::binary);

  if (!src.is_open() || !dst.is_open()) {
    return false;
  }

  dst << src.rdbuf();
  return true;
}

namespace Config {

// ConfigVersionDetector implementation
std::map<std::string, int> ConfigVersionDetector::version_markers_ = {
    {"PerformanceMonitoring", 3},
    {"ErrorHandling", 3},
    {"MemoryManagement", 2},
    {"PrometheusConfig", 2},
    {"version", 1}};

int ConfigVersionDetector::detect_version(const std::string &config_file) {
  std::ifstream file(config_file);
  if (!file.is_open()) {
    return 0; // Invalid file
  }

  std::string line;
  int detected_version = 1; // Default to version 1

  while (std::getline(file, line)) {
    line = std::regex_replace(line, std::regex("^\\s+|\\s+$"), ""); // trim

    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    // Check for section headers
    if (line[0] == '[' && line.back() == ']') {
      std::string section = line.substr(1, line.length() - 2);
      auto it = version_markers_.find(section);
      if (it != version_markers_.end()) {
        detected_version = std::max(detected_version, it->second);
      }
    }

    // Check for version key
    if (line.find("version") == 0) {
      size_t eq_pos = line.find('=');
      if (eq_pos != std::string::npos) {
        std::string version_str = line.substr(eq_pos + 1);
        version_str =
            std::regex_replace(version_str, std::regex("^\\s+|\\s+$"), "");
        try {
          detected_version = std::max(detected_version, std::stoi(version_str));
        } catch (...) {
          // Ignore invalid version numbers
        }
      }
    }
  }

  return detected_version;
}

bool ConfigVersionDetector::has_section(const std::string &config_file,
                                        const std::string &section) {
  std::ifstream file(config_file);
  if (!file.is_open()) {
    return false;
  }

  std::string line;
  std::string target_section = "[" + section + "]";

  while (std::getline(file, line)) {
    line = std::regex_replace(line, std::regex("^\\s+|\\s+$"), "");
    if (line == target_section) {
      return true;
    }
  }

  return false;
}

std::vector<std::string>
ConfigVersionDetector::get_sections(const std::string &config_file) {
  std::vector<std::string> sections;
  std::ifstream file(config_file);
  if (!file.is_open()) {
    return sections;
  }

  std::string line;
  while (std::getline(file, line)) {
    line = std::regex_replace(line, std::regex("^\\s+|\\s+$"), "");
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    if (line[0] == '[' && line.back() == ']') {
      sections.push_back(line.substr(1, line.length() - 2));
    }
  }

  return sections;
}

// ConfigMigrator implementation
ConfigMigrator::ConfigMigrator()
    : backup_directory_("./config_backups"), verbose_output_(false) {
  std::filesystem::create_directories(backup_directory_);
}

MigrationResult ConfigMigrator::migrate_config(const std::string &input_file,
                                               const std::string &output_file,
                                               bool backup_original) {
  MigrationResult result;

  if (!std::filesystem::exists(input_file)) {
    result.errors.push_back("Input file does not exist: " + input_file);
    return result;
  }

  // Detect current version
  result.version_from = ConfigVersionDetector::detect_version(input_file);
  result.version_to = 3; // Current version

  if (result.version_from == result.version_to) {
    result.success = true;
    result.warnings.push_back("Configuration is already at the latest version");
    result.output_file = input_file;
    return result;
  }

  // Create backup if requested
  std::string backup_file;
  if (backup_original) {
    backup_file = create_backup(input_file);
    if (backup_file.empty()) {
      result.errors.push_back("Failed to create backup of original file");
      return result;
    }
    result.changes_made.push_back("Created backup: " + backup_file);
  }

  // Determine output file
  result.output_file =
      output_file.empty() ? generate_output_filename(input_file) : output_file;

  // Copy input to output first
  if (!copy_file(input_file, result.output_file)) {
    result.errors.push_back("Failed to copy input file to output location");
    return result;
  }

  // Perform migration steps
  try {
    if (result.version_from == 1) {
      auto v2_result = migrate_v1_to_v2(result.output_file, result.output_file);
      result.warnings.insert(result.warnings.end(), v2_result.warnings.begin(),
                             v2_result.warnings.end());
      result.changes_made.insert(result.changes_made.end(),
                                 v2_result.changes_made.begin(),
                                 v2_result.changes_made.end());
      if (!v2_result.success) {
        result.errors.insert(result.errors.end(), v2_result.errors.begin(),
                             v2_result.errors.end());
        return result;
      }
    }

    if (result.version_from <= 2) {
      auto v3_result = migrate_v2_to_v3(result.output_file, result.output_file);
      result.warnings.insert(result.warnings.end(), v3_result.warnings.begin(),
                             v3_result.warnings.end());
      result.changes_made.insert(result.changes_made.end(),
                                 v3_result.changes_made.begin(),
                                 v3_result.changes_made.end());
      if (!v3_result.success) {
        result.errors.insert(result.errors.end(), v3_result.errors.begin(),
                             v3_result.errors.end());
        return result;
      }
    }

    result.success = true;
    log_migration_step("Migration completed successfully", result);

  } catch (const std::exception &e) {
    result.errors.push_back("Migration failed with exception: " +
                            std::string(e.what()));
  }

  return result;
}

MigrationResult
ConfigMigrator::migrate_v1_to_v2(const std::string &input_file,
                                 const std::string &output_file) {
  MigrationResult result;
  result.version_from = 1;
  result.version_to = 2;

  // Add MemoryManagement and PrometheusConfig sections
  if (!ConfigVersionDetector::has_section(input_file, "MemoryManagement")) {
    add_memory_management_section(output_file);
    result.changes_made.push_back(
        "Added MemoryManagement section with default values");
  }

  // Add PrometheusConfig section if it's missing
  if (!ConfigVersionDetector::has_section(input_file, "PrometheusConfig")) {
    std::map<std::string, std::string> prometheus_defaults = {
        {"enabled", "true"},     {"host", "localhost"},
        {"port", "9090"},        {"metrics_port", "8080"},
        {"push_interval", "10"}, {"job_name", "anomaly_detector"}};
    add_default_section(output_file, "PrometheusConfig", prometheus_defaults);
    result.changes_made.push_back(
        "Added PrometheusConfig section with default values");
  }

  result.success = true;
  return result;
}

MigrationResult
ConfigMigrator::migrate_v2_to_v3(const std::string &input_file,
                                 const std::string &output_file) {
  MigrationResult result;
  result.version_from = 2;
  result.version_to = 3;

  // Add PerformanceMonitoring section
  if (!ConfigVersionDetector::has_section(input_file,
                                          "PerformanceMonitoring")) {
    add_performance_monitoring_section(output_file);
    result.changes_made.push_back(
        "Added PerformanceMonitoring section with default values");
  }

  // Add ErrorHandling section
  if (!ConfigVersionDetector::has_section(input_file, "ErrorHandling")) {
    add_error_handling_section(output_file);
    result.changes_made.push_back(
        "Added ErrorHandling section with default values");
  }

  // Update version number in the file
  std::ifstream input(output_file);
  std::ostringstream buffer;
  std::string line;
  bool version_found = false;

  while (std::getline(input, line)) {
    if (line.find("version") == 0 && line.find("=") != std::string::npos) {
      buffer << "version = 3" << std::endl;
      version_found = true;
      result.changes_made.push_back("Updated version number to 3");
    } else {
      buffer << line << std::endl;
    }
  }
  input.close();

  // Add version if not found
  if (!version_found) {
    buffer << std::endl << "# Configuration version" << std::endl;
    buffer << "version = 3" << std::endl;
    result.changes_made.push_back("Added version number (3) to configuration");
  }

  // Write back to file
  std::ofstream output(output_file);
  output << buffer.str();
  output.close();

  result.success = true;
  return result;
}

MigrationResult
ConfigMigrator::migrate_v3_to_current(const std::string &input_file,
                                      const std::string &output_file) {
  MigrationResult result;
  result.version_from = 3;
  result.version_to = 3; // Already current
  result.success = true;
  result.warnings.push_back("Configuration is already at the current version");
  return result;
}

void ConfigMigrator::add_performance_monitoring_section(
    const std::string &config_file) {
  std::map<std::string, std::string> defaults = {
      {"enabled", "true"},
      {"collection_interval", "5"},
      {"cpu_threshold", "80.0"},
      {"memory_threshold", "85.0"},
      {"disk_threshold", "90.0"},
      {"network_threshold", "75.0"},
      {"alert_on_threshold_breach", "true"},
      {"performance_log_level", "INFO"}};
  add_default_section(config_file, "PerformanceMonitoring", defaults);
}

void ConfigMigrator::add_error_handling_section(
    const std::string &config_file) {
  std::map<std::string, std::string> defaults = {
      {"strategy", "RETRY_WITH_BACKOFF"},
      {"max_retries", "3"},
      {"retry_delay", "1000"},
      {"backoff_multiplier", "2.0"},
      {"circuit_breaker_enabled", "true"},
      {"circuit_breaker_threshold", "5"},
      {"circuit_breaker_timeout", "30000"},
      {"fallback_enabled", "true"}};
  add_default_section(config_file, "ErrorHandling", defaults);
}

void ConfigMigrator::add_memory_management_section(
    const std::string &config_file) {
  std::map<std::string, std::string> defaults = {
      {"max_memory_usage", "2048"},  {"gc_threshold", "85"},
      {"buffer_size", "8192"},       {"enable_memory_pooling", "true"},
      {"pool_initial_size", "1024"}, {"pool_max_size", "4096"},
      {"monitoring_enabled", "true"}};
  add_default_section(config_file, "MemoryManagement", defaults);
}

std::string ConfigMigrator::create_backup(const std::string &original_file) {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");

  std::filesystem::path original_path(original_file);
  std::string backup_filename = original_path.stem().string() + "_backup_" +
                                ss.str() + original_path.extension().string();
  std::string backup_path = backup_directory_ + "/" + backup_filename;

  if (copy_file(original_file, backup_path)) {
    return backup_path;
  }
  return "";
}

bool ConfigMigrator::copy_file(const std::string &source,
                               const std::string &dest) {
  try {
    std::filesystem::copy_file(
        source, dest, std::filesystem::copy_options::overwrite_existing);
    return true;
  } catch (...) {
    return false;
  }
}

std::string
ConfigMigrator::generate_output_filename(const std::string &input_file) {
  std::filesystem::path input_path(input_file);
  std::string base_name = input_path.stem().string();
  std::string extension = input_path.extension().string();

  if (base_name.find("_migrated") == std::string::npos) {
    return input_path.parent_path().string() + "/" + base_name + "_migrated" +
           extension;
  }
  return input_file;
}

void ConfigMigrator::log_migration_step(const std::string &message,
                                        MigrationResult &result) {
  if (verbose_output_) {
    result.changes_made.push_back(message);
  }
}

void ConfigMigrator::add_default_section(
    const std::string &config_file, const std::string &section,
    const std::map<std::string, std::string> &defaults) {
  std::ofstream file(config_file, std::ios::app);
  if (!file.is_open()) {
    return;
  }

  file << std::endl << "[" << section << "]" << std::endl;
  for (const auto &pair : defaults) {
    file << pair.first << " = " << pair.second << std::endl;
  }
  file << std::endl;
  file.close();
}

// ConfigValidator implementation
ConfigValidator::ValidationResult
ConfigValidator::validate_at_runtime(const AppConfig &config) {
  ValidationResult result;

  // Validate database connectivity
  auto db_result = validate_database_connectivity(config.mongo_config);
  result.errors.insert(result.errors.end(), db_result.errors.begin(),
                       db_result.errors.end());
  result.warnings.insert(result.warnings.end(), db_result.warnings.begin(),
                         db_result.warnings.end());

  // Validate Prometheus connectivity
  auto prom_result = validate_prometheus_connectivity(config.prometheus_config);
  result.errors.insert(result.errors.end(), prom_result.errors.begin(),
                       prom_result.errors.end());
  result.warnings.insert(result.warnings.end(), prom_result.warnings.begin(),
                         prom_result.warnings.end());

  // Validate file permissions
  auto file_result = validate_file_permissions(config);
  result.errors.insert(result.errors.end(), file_result.errors.begin(),
                       file_result.errors.end());
  result.warnings.insert(result.warnings.end(), file_result.warnings.begin(),
                         file_result.warnings.end());

  // Validate network ports
  auto port_result = validate_network_ports(config);
  result.errors.insert(result.errors.end(), port_result.errors.begin(),
                       port_result.errors.end());
  result.warnings.insert(result.warnings.end(), port_result.warnings.begin(),
                         port_result.warnings.end());

  // Validate memory limits
  auto memory_result = validate_memory_limits(config);
  result.errors.insert(result.errors.end(), memory_result.errors.begin(),
                       memory_result.errors.end());
  result.warnings.insert(result.warnings.end(), memory_result.warnings.begin(),
                         memory_result.warnings.end());

  result.is_valid = result.errors.empty();
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_file(const std::string &config_file) {
  ValidationResult result;

  if (!std::filesystem::exists(config_file)) {
    result.is_valid = false;
    result.errors.push_back("Configuration file does not exist: " +
                            config_file);
    return result;
  }

  // Try to parse the configuration
  try {
    ConfigManager manager;
    AppConfig config = manager.load_config(config_file);
    return validate_at_runtime(config);
  } catch (const std::exception &e) {
    result.is_valid = false;
    result.errors.push_back("Failed to parse configuration: " +
                            std::string(e.what()));
  }

  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_database_connectivity(
    const MongoLogSourceConfig &config) {
  ValidationResult result;

  // Basic validation - in a real implementation, you'd try to connect
  if (config.host.empty()) {
    result.errors.push_back("MongoDB host cannot be empty");
  }

  if (config.port <= 0 || config.port > 65535) {
    result.errors.push_back("MongoDB port must be between 1 and 65535");
  }

  if (config.database.empty()) {
    result.errors.push_back("MongoDB database name cannot be empty");
  }

  if (config.collection.empty()) {
    result.errors.push_back("MongoDB collection name cannot be empty");
  }

  result.is_valid = result.errors.empty();
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_prometheus_connectivity(
    const PrometheusConfig &config) {
  ValidationResult result;

  if (config.enabled) {
    if (config.host.empty()) {
      result.errors.push_back("Prometheus host cannot be empty when enabled");
    }

    if (config.port <= 0 || config.port > 65535) {
      result.errors.push_back("Prometheus port must be between 1 and 65535");
    }

    if (config.metrics_port <= 0 || config.metrics_port > 65535) {
      result.errors.push_back(
          "Prometheus metrics port must be between 1 and 65535");
    }

    if (config.port == config.metrics_port) {
      result.warnings.push_back(
          "Prometheus port and metrics port are the same");
    }
  }

  result.is_valid = result.errors.empty();
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_file_permissions(const AppConfig &config) {
  ValidationResult result;

  // Check if log files are writable
  for (const auto &log_source : config.log_sources) {
    if (log_source.type == "file" && !log_source.file_path.empty()) {
      std::filesystem::path log_path(log_source.file_path);
      if (!std::filesystem::exists(log_path.parent_path())) {
        result.errors.push_back("Log directory does not exist: " +
                                log_path.parent_path().string());
      }
    }
  }

  result.is_valid = result.errors.empty();
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_network_ports(const AppConfig &config) {
  ValidationResult result;

  std::set<int> used_ports;

  // Check Prometheus ports
  if (config.prometheus_config.enabled) {
    if (used_ports.count(config.prometheus_config.port)) {
      result.errors.push_back("Port conflict: " +
                              std::to_string(config.prometheus_config.port));
    }
    used_ports.insert(config.prometheus_config.port);

    if (used_ports.count(config.prometheus_config.metrics_port)) {
      result.errors.push_back(
          "Port conflict: " +
          std::to_string(config.prometheus_config.metrics_port));
    }
    used_ports.insert(config.prometheus_config.metrics_port);
  }

  result.is_valid = result.errors.empty();
  return result;
}

ConfigValidator::ValidationResult
ConfigValidator::validate_memory_limits(const AppConfig &config) {
  ValidationResult result;

  if (config.memory_config.max_memory_usage < 128) {
    result.warnings.push_back(
        "Very low memory limit: " +
        std::to_string(config.memory_config.max_memory_usage) + "MB");
  }

  if (config.memory_config.max_memory_usage > 16384) {
    result.warnings.push_back(
        "Very high memory limit: " +
        std::to_string(config.memory_config.max_memory_usage) + "MB");
  }

  if (config.memory_config.gc_threshold > 95) {
    result.warnings.push_back(
        "GC threshold is very high, may cause performance issues");
  }

  result.is_valid = result.errors.empty();
  return result;
}

// ConfigHotReloader implementation
ConfigHotReloader::ConfigHotReloader(
    std::shared_ptr<ConfigManager> config_manager)
    : config_manager_(config_manager), is_watching_(false), last_modified_(0),
      notifications_enabled_(true) {}

ConfigHotReloader::~ConfigHotReloader() { stop_watching(); }

void ConfigHotReloader::start_watching(const std::string &config_file) {
  if (is_watching_) {
    stop_watching();
  }

  watched_file_ = config_file;
  is_watching_ = true;

  // Get initial modification time
  if (std::filesystem::exists(config_file)) {
    auto file_time = std::filesystem::last_write_time(config_file);
    last_modified_ = std::chrono::duration_cast<std::chrono::seconds>(
                         file_time.time_since_epoch())
                         .count();
  }

  watcher_thread_ = std::thread(&ConfigHotReloader::watch_loop, this);
}

void ConfigHotReloader::stop_watching() {
  is_watching_ = false;
  if (watcher_thread_.joinable()) {
    watcher_thread_.join();
  }
}

bool ConfigHotReloader::is_watching() const { return is_watching_; }

bool ConfigHotReloader::reload_config() {
  try {
    AppConfig old_config = config_manager_->get_config();
    AppConfig new_config = config_manager_->load_config(watched_file_);

    // Update the config manager
    config_manager_->update_config(new_config);

    // Notify components
    notify_components(new_config, old_config);

    return true;
  } catch (const std::exception &e) {
    // Log error
    return false;
  }
}

void ConfigHotReloader::register_reload_callback(
    const std::string &component_name, ReloadCallback callback) {
  std::lock_guard<std::mutex> lock(callbacks_mutex_);
  reload_callbacks_[component_name] = callback;
}

void ConfigHotReloader::unregister_reload_callback(
    const std::string &component_name) {
  std::lock_guard<std::mutex> lock(callbacks_mutex_);
  reload_callbacks_.erase(component_name);
}

void ConfigHotReloader::watch_loop() {
  while (is_watching_) {
    if (file_changed()) {
      reload_config();
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

bool ConfigHotReloader::file_changed() {
  if (!std::filesystem::exists(watched_file_)) {
    return false;
  }

  auto file_time = std::filesystem::last_write_time(watched_file_);
  auto current_time = std::chrono::duration_cast<std::chrono::seconds>(
                          file_time.time_since_epoch())
                          .count();

  if (current_time != last_modified_) {
    last_modified_ = current_time;
    return true;
  }

  return false;
}

void ConfigHotReloader::notify_components(const AppConfig &new_config,
                                          const AppConfig &old_config) {
  if (!notifications_enabled_) {
    return;
  }

  std::lock_guard<std::mutex> lock(callbacks_mutex_);
  for (const auto &pair : reload_callbacks_) {
    try {
      pair.second(new_config, old_config);
    } catch (const std::exception &e) {
      // Log callback error
    }
  }
}

} // namespace Config
