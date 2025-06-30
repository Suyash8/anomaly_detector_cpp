#include "analysis/session_features.hpp"

#include <cstddef>
#include <optional>

std::optional<SessionFeatures>
SessionFeatureExtractor::extract(const PerSessionState &session) {
  if (session.request_count < 2)
    return std::nullopt;

  SessionFeatures features;

  double total_time_diff = 0.0;
  for (size_t i = 1; i < session.request_history.size(); ++i)
    total_time_diff += (session.request_history[i].first -
                        session.request_history[i - 1].first) /
                       1000.0;
  features.avg_time_between_request_s =
      total_time_diff / (session.request_history.size() - 1);

  int get_count = session.http_method_counts.count("GET")
                      ? session.http_method_counts.at("GET")
                      : 0;
  int post_count = session.http_method_counts.count("POST")
                       ? session.http_method_counts.at("POST")
                       : 0;
  if (get_count > 0)
    features.post_to_get_ratio = static_cast<double>(post_count) / get_count;

  features.ua_changes_in_session = session.unique_user_agents.size();

  return features;
}