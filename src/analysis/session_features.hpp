#ifndef SESSION_FEATURES_HPP
#define SESSION_FEATURES_HPP

#include "analysis/per_session_state.hpp"

#include <cstdint>
#include <optional>

struct SessionFeatures {
  double avg_time_between_request_s = 0.0;
  double post_to_get_ratio = 0.0;
  uint32_t ua_changes_in_session = 0;
};

class SessionFeatureExtractor {
public:
  static std::optional<SessionFeatures> extract(const PerSessionState &session);
};

#endif // SESSION_FEATURES_HPP