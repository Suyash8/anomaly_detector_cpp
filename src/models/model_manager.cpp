#include "models/model_manager.hpp"
#include "models/onnx_model.hpp"
#include <cstdio>
#include <cstdlib>
#include <iostream>

ModelManager::ModelManager(const Config::AppConfig &config) : config_(config) {
  // Initial load of the model
  if (config_.tier3.enabled) {
    try {
      active_model_ = std::make_unique<ONNXModel>(
          config_.tier3.model_path, config_.tier3.model_metadata_path);
    } catch (...) { /* Error already logged by ONNXModel constructor */
    }
  }

  // Start background thread if retraining is enabled
  if (config_.tier3.automated_retraining_enabled) {
    background_thread_ =
        std::thread(&ModelManager::background_thread_func, this);
  }
}

ModelManager::~ModelManager() {
  if (background_thread_.joinable()) {
    shutdown_flag_ = true;
    cv_.notify_one();
    background_thread_.join();
  }
}

void ModelManager::background_thread_func() {
  while (!shutdown_flag_) {
    std::unique_lock<std::mutex> lock(cv_mutex_);
    // Sleep for the configured interval, but allow shutdown to interrupt it
    if (cv_.wait_for(
            lock,
            std::chrono::seconds(config_.tier3.retraining_interval_seconds),
            [this] { return shutdown_flag_.load(); })) {
      break; // Shutdown was requested
    }

    std::cout << "[ModelManager] Kicking off scheduled model retraining..."
              << std::endl;
    attempt_retrain_and_swap();
  }
}

void ModelManager::attempt_retrain_and_swap() {
  // 1. Trigger the Python training script
  // Note: A more robust solution might use python-C-API, but std::system is
  // simplest for this scope.
  std::string command = "python3 " + config_.tier3.training_script_path;
  int result = std::system(command.c_str());

  if (result != 0) {
    std::cerr << "[ModelManager] Python training script failed with exit code: "
              << result << std::endl;
    return;
  }

  // 2. Define paths for the new model
  std::string new_model_path = config_.tier3.model_path + ".new";
  std::string new_metadata_path = config_.tier3.model_metadata_path + ".new";

  // The script should save to the primary paths, so we rename them to our .new
  // temp paths
  std::rename(config_.tier3.model_path.c_str(), new_model_path.c_str());
  std::rename(config_.tier3.model_metadata_path.c_str(),
              new_metadata_path.c_str());

  // 3. Attempt to load the new model
  std::cout << "[ModelManager] Attempting to load newly trained model..."
            << std::endl;
  try {
    auto new_model =
        std::make_shared<ONNXModel>(new_model_path, new_metadata_path);
    if (new_model && new_model->is_ready()) {
      // 4. Hot-swap the active model
      {
        std::lock_guard<std::mutex> lock(model_mutex_);
        active_model_ = new_model;
      }

      // 5. Promote the new files and clean up old
      std::cout << "[ModelManager] New model hot-swapped successfully. "
                   "Promoting new model files."
                << std::endl;
      std::rename(new_model_path.c_str(), config_.tier3.model_path.c_str());
      std::rename(new_metadata_path.c_str(),
                  config_.tier3.model_metadata_path.c_str());
    } else {
      std::cerr << "[ModelManager] Newly trained model failed to load. "
                   "Reverting to old model."
                << std::endl;
      std::remove(new_model_path.c_str());
      std::remove(new_metadata_path.c_str());
    }
  } catch (...) {
    std::cerr
        << "[ModelManager] Exception caught while loading new model. Reverting."
        << std::endl;
    std::remove(new_model_path.c_str());
    std::remove(new_metadata_path.c_str());
  }
}

std::shared_ptr<IAnomalyModel> ModelManager::get_active_model() const {
  std::lock_guard<std::mutex> lock(model_mutex_);
  return active_model_;
}

void ModelManager::reconfigure(const Config::AppConfig &new_config) {
  std::lock_guard<std::mutex> lock(model_mutex_);
  config_ = new_config;
  // Logic to restart the thread if interval changes could go here
  // For now, a full app restart is needed to change the timer
}