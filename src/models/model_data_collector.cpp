#include "models/model_data_collector.hpp"
#include "utils/utils.hpp"

#include <iostream>
#include <mutex>
#include <sstream>
#include <vector>

ModelDataCollector::ModelDataCollector(const std::string &output_path) {
  if (!output_path.empty()) {
    Utils::create_directory_for_file(output_path);
    output_file_.open(output_path, std::ios::out | std::ios::app);
    if (!output_file_.is_open())
      std::cerr << "Error: Could not open ML data collection file: "
                << output_path << std::endl;
  }
}

ModelDataCollector::~ModelDataCollector() {
  if (output_file_.is_open())
    output_file_.close();
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
}