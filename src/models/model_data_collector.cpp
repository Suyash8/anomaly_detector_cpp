#include "models/model_data_collector.hpp"
#include "core/logger.hpp"
#include "utils/utils.hpp"

#include <iostream>
#include <mutex>
#include <sstream>
#include <vector>

ModelDataCollector::ModelDataCollector(const std::string &output_path) {
  if (!output_path.empty()) {
    Utils::create_directory_for_file(output_path);
    output_file_.open(output_path, std::ios::out | std::ios::app);
    if (!output_file_.is_open()) {
      LOG(LogLevel::ERROR, LogComponent::ML_FEATURES,
          "Could not open ML data collection file: " << output_path);
      return;
    }
    LOG(LogLevel::INFO, LogComponent::ML_FEATURES,
        "ModelDataCollector initialized. Data will be collected to: "
            << output_path);
  }
}

ModelDataCollector::~ModelDataCollector() {
  if (output_file_.is_open())
    output_file_.close();
  LOG(LogLevel::INFO, LogComponent::ML_FEATURES,
      "ModelDataCollector destroyed. Data collection file closed.");
}

void ModelDataCollector::collect_features(const std::vector<double> &features) {
  if (!output_file_.is_open() || features.empty())
    return;

  std::stringstream ss;
  for (size_t i = 0; i < features.size(); ++i)
    ss << features[i] << (i == features.size() - 1 ? "" : ",");

  ss << "\n";

  // Lock mutex to ensure thread-safe writes if we ever multi-thread the
  // pipeline
  std::lock_guard<std::mutex> lock(file_mutex_);
  output_file_ << ss.str();

  LOG(LogLevel::DEBUG, LogComponent::ML_FEATURES,
      "Collected features: " << ss.str()
                             << " | Total features: " << features.size());
}