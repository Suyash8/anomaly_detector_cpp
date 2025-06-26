#include "features.hpp"

std::string get_feature_name(Feature f) {
  switch (f) {
  case Feature::REQUEST_TIME_S:
    return "REQUEST_TIME_S";
  case Feature::BYTES_SENT:
    return "BYTES_SENT";
  case Feature::HTTP_STATUS_4XX:
    return "HTTP_STATUS_4XX";
  case Feature::HTTP_STATUS_5XX:
    return "HTTP_STATUS_5XX";
  case Feature::IS_UA_MISSING:
    return "IS_UA_MISSING";
  case Feature::IS_UA_HEADLESS:
    return "IS_UA_HEADLESS";
  case Feature::IS_UA_KNOWN_BAD:
    return "IS_UA_KNOWN_BAD";
  case Feature::IS_UA_CYCLING:
    return "IS_UA_CYCLING";
  case Feature::IS_PATH_NEW_FOR_IP:
    return "IS_PATH_NEW_FOR_IP";
  case Feature::IP_REQ_TIME_ZSCORE:
    return "IP_REQ_TIME_ZSCORE";
  case Feature::IP_BYTES_SENT_ZSCORE:
    return "IP_BYTES_SENT_ZSCORE";
  case Feature::IP_ERROR_EVENT_ZSCORE:
    return "IP_ERROR_EVENT_ZSCORE";
  case Feature::IP_REQ_VOL_ZSCORE:
    return "IP_REQ_VOL_ZSCORE";
  case Feature::PATH_REQ_TIME_ZSCORE:
    return "PATH_REQ_TIME_ZSCORE";
  case Feature::PATH_BYTES_SENT_ZSCORE:
    return "PATH_BYTES_SENT_ZSCORE";
  case Feature::PATH_ERROR_EVENT_ZSCORE:
    return "PATH_ERROR_EVENT_ZSCORE";
  default:
    return "UNKNOWN_FEATURE";
  }
}