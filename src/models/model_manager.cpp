#include "models/model_manager.hpp"
#include "core/logger.hpp" // NEW: Include the logger
#include "models/onnx_model.hpp"
#include <chrono> // NEW: Include for chrono literals
#include <cstdio>
#include <cstdlib>

ModelManager::ModelManager(const Config::AppConfig &config) : config_(config) {
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE, "ModelManager created.");
  // Initial load of the model
  if (config_.tier3.enabled) {
    LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
        "Tier 3 is enabled. Attempting to load initial ONNX model.");
    try {
      active_model_ = std::make_unique<ONNXModel>(
          config_.tier3.model_path, config_.tier3.model_metadata_path);
      if (active_model_) {
        LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
            "Initial model loaded successfully.");
      } else {
        LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
            "Initial model failed to load. Tier 3 will be inactive.");
        active_model_.reset();
      }
    } catch (const std::exception &e) {
      LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
          "Exception caught during initial model load: " << e.what());
      // Error is already logged by ONNXModel constructor
    }
  } else {
    LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
        "Tier 3 is disabled. No model will be loaded.");
  }

  // Start background thread if retraining is enabled
  if (config_.tier3.automated_retraining_enabled) {
    LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
        "Automated retraining is enabled. Starting background thread.");
    background_thread_ =
        std::thread(&ModelManager::background_thread_func, this);
  } else {
    LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
        "Automated retraining is disabled.");
  }
}

ModelManager::~ModelManager() {
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Shutting down ModelManager...");
  if (background_thread_.joinable()) {
    shutdown_flag_ = true;
    cv_.notify_one();
    background_thread_.join();
    LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
        "Background retraining thread joined successfully.");
  }
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE, "ModelManager shut down.");
}

void ModelManager::background_thread_func() {
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Background retraining thread started. Waiting for initial interval.");
  while (!shutdown_flag_) {
    std::unique_lock<std::mutex> lock(cv_mutex_);

    using namespace std::chrono_literals;
    auto wait_duration =
        std::chrono::seconds(config_.tier3.retraining_interval_seconds);
    LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
        "Retraining thread now sleeping for "
            << config_.tier3.retraining_interval_seconds << " seconds.");

    // Sleep for the configured interval, but allow shutdown to interrupt it
    if (cv_.wait_for(lock, wait_duration,
                     [this] { return shutdown_flag_.load(); })) {
      LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
          "Shutdown requested, exiting retraining thread sleep.");
      break; // Shutdown was requested
    }

    // If we are here, the timer expired naturally.
    if (shutdown_flag_)
      break;

    LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
        "Scheduled retraining interval elapsed. Kicking off model "
        "retraining...");
    attempt_retrain_and_swap();
  }
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Background retraining thread finished.");
}

void ModelManager::attempt_retrain_and_swap() {
  LOG(LogLevel::TRACE, LogComponent::ML_LIFECYCLE,
      "Entering attempt_retrain_and_swap.");

  // 1. Trigger the Python training script
  // Note: A more robust solution might use python-C-API, but std::system is
  // simplest for this scope.
  std::string command = "python3 " + config_.tier3.training_script_path;
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Executing training script with command: " << command);
  int result = std::system(command.c_str());

  if (result != 0) {
    LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
        "Python training script failed with non-zero exit code: "
            << result << ". Aborting model swap.");
    return;
  }
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Python training script completed successfully.");

  // 2. Define paths for the new model. The script is expected to have
  // overwritten the original files. We rename the newly created files to
  // temporary names to attempt a safe load.
  std::string original_model_path = config_.tier3.model_path;
  std::string original_metadata_path = config_.tier3.model_metadata_path;

  std::string temp_model_path = original_model_path + ".new";
  std::string temp_metadata_path = original_metadata_path + ".new";

  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Renaming new model " << original_model_path << " to "
                            << temp_model_path);
  if (std::rename(original_model_path.c_str(), temp_model_path.c_str()) != 0) {
    LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
        "Failed to rename new model file. Aborting swap.");
    return;
  }

  LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
      "Renaming new metadata " << original_metadata_path << " to "
                               << temp_metadata_path);
  if (std::rename(original_metadata_path.c_str(), temp_metadata_path.c_str()) !=
      0) {
    LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
        "Failed to rename new metadata file. Cleaning up and aborting swap.");
    std::rename(temp_model_path.c_str(),
                original_model_path.c_str()); // Put the model file back
    return;
  }

  // 3. Attempt to load the new model from the temporary paths
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "Attempting to load newly trained model from temporary files...");
  try {
    auto new_model =
        std::make_shared<ONNXModel>(temp_model_path, temp_metadata_path);

    if (new_model && new_model->is_ready()) {
      LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
          "New model loaded successfully from temporary files. Proceeding to "
          "hot-swap.");
      // 4. Hot-swap the active model pointer
      {
        std::lock_guard<std::mutex> lock(model_mutex_);
        active_model_ = new_model;
        LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
            "Model hot-swap complete. New model is now active.");
      }

      // 5. Promote the new files by renaming them back to the original paths
      LOG(LogLevel::DEBUG, LogComponent::ML_LIFECYCLE,
          "Promoting new model files to primary paths.");
      std::rename(temp_model_path.c_str(), original_model_path.c_str());
      std::rename(temp_metadata_path.c_str(), original_metadata_path.c_str());

    } else {
      LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
          "Newly trained model failed to load or is not ready. Reverting to "
          "old model.");
      std::remove(temp_model_path.c_str());
      std::remove(temp_metadata_path.c_str());
    }
  } catch (const std::exception &e) {
    LOG(LogLevel::ERROR, LogComponent::ML_LIFECYCLE,
        "Exception caught while loading new model: " << e.what()
                                                     << ". Reverting.");
    std::remove(temp_model_path.c_str());
    std::remove(temp_metadata_path.c_str());
  }
}

std::shared_ptr<IAnomalyModel> ModelManager::get_active_model() const {
  LOG(LogLevel::TRACE, LogComponent::ML_LIFECYCLE,
      "get_active_model called, acquiring lock...");
  std::lock_guard<std::mutex> lock(model_mutex_);
  LOG(LogLevel::TRACE, LogComponent::ML_LIFECYCLE,
      "get_active_model returning model pointer.");
  return active_model_;
}

void ModelManager::reconfigure(const Config::AppConfig &new_config) {
  LOG(LogLevel::TRACE, LogComponent::ML_LIFECYCLE,
      "reconfigure called, acquiring lock...");
  std::lock_guard<std::mutex> lock(model_mutex_);
  config_ = new_config;
  LOG(LogLevel::INFO, LogComponent::ML_LIFECYCLE,
      "ModelManager reconfigured. Note: Retraining interval changes require an "
      "application restart.");
  // Logic to restart the thread if interval changes could go here
  // For now, a full app restart is needed to change the timer
}