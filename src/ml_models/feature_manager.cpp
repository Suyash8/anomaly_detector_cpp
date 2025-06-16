#include "feature_manager.hpp"
#include "features.hpp"
#include <cstddef>
#include <vector>

FeatureManager::FeatureManager() {
  // Initialize min-max scaling parameters for each feature
  // These are educated guesses for now
  min_max_params_.resize(static_cast<size_t>(Feature::FEATURE_COUNT));

  // Format: {min_val, max_val}
  min_max_params_[static_cast<int>(Feature::REQUEST_TIME_S)] = {
      0.0, 10.0}; // 0-10 seconds
  min_max_params_[static_cast<int>(Feature::BYTES_SENT)] = {0.0,
                                                            20000.0}; // 0-20KB
  min_max_params_[static_cast<int>(Feature::HTTP_STATUS_4XX)] = {0.0,
                                                                 1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::HTTP_STATUS_5XX)] = {0.0,
                                                                 1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::IS_UA_MISSING)] = {0.0,
                                                               1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::IS_UA_HEADLESS)] = {0.0,
                                                                1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::IS_UA_KNOWN_BAD)] = {0.0,
                                                                 1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::IS_UA_CYCLING)] = {0.0,
                                                               1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::IS_PATH_NEW_FOR_IP)] = {
      0.0, 1.0}; // Binary
  min_max_params_[static_cast<int>(Feature::IP_REQ_TIME_ZSCORE)] = {
      -5.0, 5.0}; // Z-scores typically in this range
  min_max_params_[static_cast<int>(Feature::IP_BYTES_SENT_ZSCORE)] = {-5.0,
                                                                      5.0};
  min_max_params_[static_cast<int>(Feature::IP_ERROR_EVENT_ZSCORE)] = {-5.0,
                                                                       5.0};
  min_max_params_[static_cast<int>(Feature::IP_REQ_VOL_ZSCORE)] = {-5.0, 5.0};
  min_max_params_[static_cast<int>(Feature::PATH_REQ_TIME_ZSCORE)] = {-5.0,
                                                                      5.0};
  min_max_params_[static_cast<int>(Feature::PATH_BYTES_SENT_ZSCORE)] = {-5.0,
                                                                        5.0};
  min_max_params_[static_cast<int>(Feature::PATH_ERROR_EVENT_ZSCORE)] = {-5.0,
                                                                         5.0};
}

double FeatureManager::normalize(double value, Feature f) {
  const auto &param = min_max_params_[static_cast<int>(f)];
  double min_value = param.first;
  double max_value = param.second;

  if ((max_value - min_value) == 0)
    return 0.5; // Avoid div by zero, reutrn neutral value

  double normalized = (value - min_value) / (max_value - min_value);

  // Clamp the result to the [0.0, 1.0] range
  return std::max(0.0, std::min(1.0, normalized));
}

std::vector<double>
FeatureManager::extract_and_normalize(const AnalyzedEvent &event) {
  std::vector<double> features(static_cast<size_t>(Feature::FEATURE_COUNT),
                               0.0);

  // Helper lambda to safely get value from optional or return a default (0.0)
  auto get_val = [](const std::optional<double> &opt) {
    return opt.value_or(0.0);
  };

  // --- Extraction ---
  features[static_cast<int>(Feature::REQUEST_TIME_S)] =
      event.raw_log.request_time_s.value_or(0.0);
  features[static_cast<int>(Feature::BYTES_SENT)] =
      static_cast<double>(event.raw_log.bytes_sent.value_or(0));
  int status = event.raw_log.http_status_code.value_or(0);
  features[static_cast<int>(Feature::HTTP_STATUS_4XX)] =
      (status >= 400 && status < 500) ? 1.0 : 0.0;
  features[static_cast<int>(Feature::HTTP_STATUS_5XX)] =
      (status >= 500 && status < 600) ? 1.0 : 0.0;
  features[static_cast<int>(Feature::IS_UA_MISSING)] =
      event.is_ua_missing ? 1.0 : 0.0;
  features[static_cast<int>(Feature::IS_UA_HEADLESS)] =
      event.is_ua_headless ? 1.0 : 0.0;
  features[static_cast<int>(Feature::IS_UA_KNOWN_BAD)] =
      event.is_ua_known_bad ? 1.0 : 0.0;
  features[static_cast<int>(Feature::IS_UA_CYCLING)] =
      event.is_ua_cycling ? 1.0 : 0.0;
  features[static_cast<int>(Feature::IS_PATH_NEW_FOR_IP)] =
      event.is_path_new_for_ip ? 1.0 : 0.0;
  features[static_cast<int>(Feature::IP_REQ_TIME_ZSCORE)] =
      get_val(event.ip_req_time_zscore);
  features[static_cast<int>(Feature::IP_BYTES_SENT_ZSCORE)] =
      get_val(event.ip_bytes_sent_zscore);
  features[static_cast<int>(Feature::IP_ERROR_EVENT_ZSCORE)] =
      get_val(event.ip_error_event_zscore);
  features[static_cast<int>(Feature::IP_REQ_VOL_ZSCORE)] =
      get_val(event.ip_req_vol_zscore);
  features[static_cast<int>(Feature::PATH_REQ_TIME_ZSCORE)] =
      get_val(event.path_req_time_zscore);
  features[static_cast<int>(Feature::PATH_BYTES_SENT_ZSCORE)] =
      get_val(event.path_bytes_sent_zscore);
  features[static_cast<int>(Feature::PATH_ERROR_EVENT_ZSCORE)] =
      get_val(event.path_error_event_zscore);

  // --- Normalization ---
  for (size_t i = 0; i < features.size(); ++i) {
    features[i] = normalize(features[i], static_cast<Feature>(i));
  }

  return features;
}