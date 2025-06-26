#ifndef FEATURES_HPP
#define FEATURES_HPP

#include <string>

enum class Feature {
  // Raw log features
  REQUEST_TIME_S,
  BYTES_SENT,
  HTTP_STATUS_4XX, // Binary flag: 1.0 if 4XX, 0.0 otherwise
  HTTP_STATUS_5XX, // Binary flag: 1.0 if 5XX, 0.0 otherwise

  // Heuristic/Contextual features from AnalysisEngine
  IS_UA_MISSING,
  IS_UA_HEADLESS,
  IS_UA_KNOWN_BAD,
  IS_UA_CYCLING,
  IS_PATH_NEW_FOR_IP,

  // Statistical features
  IP_REQ_TIME_ZSCORE,
  IP_BYTES_SENT_ZSCORE,
  IP_ERROR_EVENT_ZSCORE,
  IP_REQ_VOL_ZSCORE,
  PATH_REQ_TIME_ZSCORE,
  PATH_BYTES_SENT_ZSCORE,
  PATH_ERROR_EVENT_ZSCORE,

  // Total num of features
  FEATURE_COUNT
};

std::string get_feature_name(Feature f);

#endif // FEATURES_HPP