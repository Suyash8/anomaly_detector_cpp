#ifndef MODEL_MANAGER_HPP
#define MODEL_MANAGER_HPP

#include "core/config.hpp"
#include "models/base_model.hpp"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

class ModelManager {
public:
  explicit ModelManager(const Config::AppConfig &config);
  ~ModelManager();

  // Provides thread-safe access to the currently active model
  std::shared_ptr<IAnomalyModel> get_active_model() const;
  void reconfigure(const Config::AppConfig &new_config);

private:
  void background_thread_func();
  void attempt_retrain_and_swap();

  Config::AppConfig config_;

  std::shared_ptr<IAnomalyModel> active_model_;
  mutable std::mutex model_mutex_;

  std::thread background_thread_;
  std::atomic<bool> shutdown_flag_{false};
  std::condition_variable cv_;
  std::mutex cv_mutex_;
};

#endif // MODEL_MANAGER_HPP