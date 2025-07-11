#include "feature_manager.hpp"
#include "core/logger.hpp"
#include "features.hpp"

#include <cstddef>
#include <sstream>
#include <vector>

std::vector<double>
FeatureManager::extract_and_normalize(const AnalyzedEvent &event) {
  LOG(LogLevel::TRACE, LogComponent::ML_FEATURES,
      "Entering extract_and_normalize for event on line "
          << event.raw_log.original_line_number);

  // Initialize a vector of the correct size with all zeros
  std::vector<double> features(static_cast<size_t>(Feature::FEATURE_COUNT),
                               0.0);

  // Helper lambda to safely get value from optional or return a default (0.0)
  auto get_val = [](const std::optional<double> &opt) {
    return opt.value_or(0.0);
  };

  // --- Raw Request Features ---
  features[static_cast<int>(Feature::REQUEST_TIME_S)] =
      event.raw_log.request_time_s.value_or(0.0);
  features[static_cast<int>(Feature::BYTES_SENT)] =
      static_cast<double>(event.raw_log.bytes_sent.value_or(0));
  int status = event.raw_log.http_status_code.value_or(0);
  features[static_cast<int>(Feature::HTTP_STATUS_4XX)] =
      (status >= 400 && status < 500) ? 1.0 : 0.0;
  features[static_cast<int>(Feature::HTTP_STATUS_5XX)] =
      (status >= 500 && status < 600) ? 1.0 : 0.0;

  // --- IP-Centric Binary Flags ---
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

  // --- IP-Centric Statistical Features (Z-Scores) ---
  features[static_cast<int>(Feature::IP_REQ_TIME_ZSCORE)] =
      get_val(event.ip_req_time_zscore);
  features[static_cast<int>(Feature::IP_BYTES_SENT_ZSCORE)] =
      get_val(event.ip_bytes_sent_zscore);
  features[static_cast<int>(Feature::IP_ERROR_EVENT_ZSCORE)] =
      get_val(event.ip_error_event_zscore);
  features[static_cast<int>(Feature::IP_REQ_VOL_ZSCORE)] =
      get_val(event.ip_req_vol_zscore);

  // --- Path-Centric Statistical Features (Z-Scores) ---
  features[static_cast<int>(Feature::PATH_REQ_TIME_ZSCORE)] =
      get_val(event.path_req_time_zscore);
  features[static_cast<int>(Feature::PATH_BYTES_SENT_ZSCORE)] =
      get_val(event.path_bytes_sent_zscore);
  features[static_cast<int>(Feature::PATH_ERROR_EVENT_ZSCORE)] =
      get_val(event.path_error_event_zscore);

  // --- Session Features ---
  // Safely check if session context exists before trying to access it
  if (event.raw_session_state) {
    LOG(LogLevel::TRACE, LogComponent::ML_FEATURES,
        "Extracting features from session context.");
    const auto &session_raw = *event.raw_session_state;

    // --- Session-Centric Raw Features ---
    if (session_raw.session_start_timestamp_ms > 0) {
      features[static_cast<int>(Feature::SESSION_DURATION_S)] =
          (session_raw.last_seen_timestamp_ms -
           session_raw.session_start_timestamp_ms) /
          1000.0;
    }
    features[static_cast<int>(Feature::SESSION_REQ_COUNT)] =
        static_cast<double>(session_raw.request_count);
    features[static_cast<int>(Feature::SESSION_UNIQUE_PATH_COUNT)] =
        static_cast<double>(session_raw.unique_paths_visited.size());
    features[static_cast<int>(Feature::SESSION_ERROR_4XX_COUNT)] =
        static_cast<double>(session_raw.error_4xx_count);
    features[static_cast<int>(Feature::SESSION_ERROR_5XX_COUNT)] =
        static_cast<double>(session_raw.error_5xx_count);
    features[static_cast<int>(Feature::SESSION_FAILED_LOGIN_COUNT)] =
        static_cast<double>(session_raw.failed_login_attempts);
    features[static_cast<int>(Feature::SESSION_BYTES_SENT_MEAN)] =
        session_raw.bytes_sent_tracker.get_mean();
    features[static_cast<int>(Feature::SESSION_REQ_TIME_MEAN)] =
        session_raw.request_time_tracker.get_mean();

    // --- Session-Centric Derived Features ---
    if (event.derived_session_features) {
      const auto &session_derived = *event.derived_session_features;
      features[static_cast<int>(Feature::SESSION_AVG_TIME_BETWEEN_REQS_S)] =
          session_derived.avg_time_between_request_s;
      features[static_cast<int>(Feature::SESSION_POST_TO_GET_RATIO)] =
          session_derived.post_to_get_ratio;
      features[static_cast<int>(Feature::SESSION_UA_CHANGE_COUNT)] =
          static_cast<double>(session_derived.ua_changes_in_session);
    }
  }

  // Log raw features before normalization for debugging
  if (LogManager::instance().should_log(LogLevel::TRACE,
                                        LogComponent::ML_FEATURES)) {
    std::ostringstream ss;
    ss << "Raw feature vector: [";
    for (size_t i = 0; i < features.size(); ++i) {
      ss << features[i] << (i == features.size() - 1 ? "" : ", ");
    }
    ss << "]";
    LOG(LogLevel::TRACE, LogComponent::ML_FEATURES, ss.str());
  }

  // --- Final Normalization Step ---
  for (double &feature : features) {
    feature = normalize(feature);
  }

  // Log normalized features for debugging
  if (LogManager::instance().should_log(LogLevel::TRACE,
                                        LogComponent::ML_FEATURES)) {
    std::ostringstream ss;
    ss << "Normalized feature vector: [";
    for (size_t i = 0; i < features.size(); ++i) {
      ss << features[i] << (i == features.size() - 1 ? "" : ", ");
    }
    ss << "]";
    LOG(LogLevel::TRACE, LogComponent::ML_FEATURES, ss.str());
  }

  return features;
}