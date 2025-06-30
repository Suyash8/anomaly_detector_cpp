#ifndef FEATURES_HPP
#define FEATURES_HPP

#include <string>

enum class Feature {
  // --- Raw Request Features ---
  REQUEST_TIME_S,
  BYTES_SENT,
  HTTP_STATUS_4XX, // Binary: 1 if 4xx, 0 otherwise
  HTTP_STATUS_5XX, // Binary: 1 if 5xx, 0 otherwise

  // --- IP-Centric Binary Flags ---
  IS_UA_MISSING,
  IS_UA_HEADLESS,
  IS_UA_KNOWN_BAD,
  IS_UA_CYCLING,
  IS_PATH_NEW_FOR_IP,

  // --- IP-Centric Statistical Features (Z-Scores) ---
  IP_REQ_TIME_ZSCORE,
  IP_BYTES_SENT_ZSCORE,
  IP_ERROR_EVENT_ZSCORE,
  IP_REQ_VOL_ZSCORE,

  // --- Path-Centric Statistical Features (Z-Scores) ---
  PATH_REQ_TIME_ZSCORE,
  PATH_BYTES_SENT_ZSCORE,
  PATH_ERROR_EVENT_ZSCORE,

  // --- Session-Centric Raw Features ---
  SESSION_DURATION_S,
  SESSION_REQ_COUNT,
  SESSION_UNIQUE_PATH_COUNT,
  SESSION_ERROR_4XX_COUNT,
  SESSION_ERROR_5XX_COUNT,
  SESSION_FAILED_LOGIN_COUNT,

  // --- Session-Centric Derived Features ---
  SESSION_AVG_TIME_BETWEEN_REQS_S,
  SESSION_POST_TO_GET_RATIO,
  SESSION_UA_CHANGE_COUNT,
  SESSION_BYTES_SENT_MEAN,
  SESSION_REQ_TIME_MEAN,

  // This must always be the last item. It automatically provides the total
  // count.
  FEATURE_COUNT
};

std::string get_feature_name(Feature f);

#endif // FEATURES_HPP