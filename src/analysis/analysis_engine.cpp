#include "analysis_engine.hpp"
#include "analysis/per_session_state.hpp"
#include "analyzed_event.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "models/feature_manager.hpp"
#include "utils/scoped_timer.hpp"
#include "utils/ua_parser.hpp"
#include "utils/utils.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <string_view>

enum class RequestType { HTML, ASSET, OTHER };

constexpr uint32_t STATE_FILE_VERSION = 1;

RequestType get_request_type(const std::string &raw_path,
                             const Config::Tier1Config &cfg) {

  std::string path = raw_path;
  size_t query_pos = path.find('?');
  if (query_pos != std::string::npos)
    path = path.substr(0, query_pos);

  size_t fragment_pos = path.find('#');
  if (fragment_pos != std::string::npos)
    path = path.substr(0, fragment_pos);

  for (const auto &exact : cfg.html_exact_paths) {
    if (path == exact)
      return RequestType::HTML;
  }

  for (const auto &prefix : cfg.asset_path_prefixes) {
    if (path.rfind(prefix, 0) == 0)
      return RequestType::ASSET;
  }

  size_t last_dot = path.rfind('.');
  if (last_dot != std::string::npos) {
    std::string suffix = path.substr(last_dot);

    for (const auto &s : cfg.html_path_suffixes) {
      if (suffix == s)
        return RequestType::HTML;
    }

    for (const auto &s : cfg.asset_path_suffixes) {
      if (suffix == s)
        return RequestType::ASSET;
    }
  }

  return RequestType::OTHER;
}

AnalysisEngine::AnalysisEngine(const Config::AppConfig &cfg)
    : app_config(cfg), feature_manager_() {
  LOG(LogLevel::INFO, LogComponent::ANALYSIS_LIFECYCLE,
      "AnalysisEngine created.");

  if (app_config.ml_data_collection_enabled) {
    data_collector_ = std::make_unique<ModelDataCollector>(
        app_config.ml_data_collection_path);
    LOG(LogLevel::INFO, LogComponent::ML_FEATURES,
        "ML data collection enabled. Outputting features to: "
            << app_config.ml_data_collection_path);
  }
}

AnalysisEngine::~AnalysisEngine() {}

PerIpState &
AnalysisEngine::get_or_create_ip_state(const std::string &ip,
                                       uint64_t current_timestamp_ms) {
  auto it = ip_activity_trackers.find(ip);
  if (it == ip_activity_trackers.end()) {
    LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_LIFECYCLE,
        "Creating new PerIpState for IP: " << ip);
    uint64_t window_duration_ms =
        app_config.tier1.sliding_window_duration_seconds * 1000;

    // Assuming failed login window uses the same duration for now
    auto [inserted_it, success] = ip_activity_trackers.emplace(
        ip, PerIpState(current_timestamp_ms, window_duration_ms,
                       window_duration_ms));

    return inserted_it->second;
  } else {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "Found existing PerIpState for IP: "
            << ip << ". Updating last_seen timestamp.");
    it->second.last_seen_timestamp_ms = current_timestamp_ms;
    return it->second;
  }
}

PerPathState &
AnalysisEngine::get_or_create_path_state(const std::string &path,
                                         uint64_t current_timestamp_ms) {
  auto it = path_activity_trackers.find(path);
  if (it == path_activity_trackers.end()) {
    LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_LIFECYCLE,
        "Creating new PerPathState for Path: " << path);
    auto [inserted_it, success] = path_activity_trackers.emplace(
        path, PerPathState(current_timestamp_ms));
    return inserted_it->second;
  } else {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "Found existing PerPathState for Path: "
            << path << ". Updating last_seen timestamp.");
    it->second.last_seen_timestamp_ms = current_timestamp_ms;
    return it->second;
  }
}

std::string AnalysisEngine::build_session_key(const LogEntry &raw_log) const {
  std::string session_key;

  for (const auto &component : app_config.tier1.session_key_components) {
    if (component == "ip")
      session_key += raw_log.ip_address;
    else if (component == "ua")
      session_key += raw_log.user_agent;

    session_key += '|';
  }
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_SESSION,
      "Built session key: " << session_key);
  return session_key;
}

void perform_advanced_ua_analysis(const std::string &ua,
                                  const Config::Tier1Config &cfg,
                                  PerIpState &ip_state, AnalyzedEvent &event,
                                  uint64_t ts, uint64_t max_ts) {
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
      "Performing advanced UA analysis.");
  if (!cfg.check_user_agent_anomalies) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "UA analysis is disabled in config, skipping.");
    return;
  }

  // 1. Missing UA
  if (ua.empty() || ua == "-") {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE, "UA is missing.");
    event.is_ua_missing = true;
    return;
  }

  // 2. Headless/Known Bad Bot detection
  for (const auto &headless_str : cfg.headless_browser_substrings)
    if (ua.find(headless_str) != std::string::npos) {
      LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
          "Found headless browser string '" << headless_str << "' in UA.");
      event.is_ua_headless = true;
      break;
    }
  if (ua.find("sqlmap") != std::string::npos ||
      ua.find("Nmap") != std::string::npos) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "Found known bad bot string in UA.");
    event.is_ua_known_bad = true;
  }

  // 3. Version Check
  if (auto ver = UAParser::get_major_version(ua, "Chrome/");
      ver && *ver < cfg.min_chrome_version) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "Detected outdated Chrome version: " << *ver);
    event.is_ua_outdated = true;
    event.detected_browser_version = "Chrome/" + std::to_string(*ver);
  } else if (auto ver = UAParser::get_major_version(ua, "Firefox/");
             ver && *ver < cfg.min_firefox_version) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "Detected outdated Firefox version: " << *ver);
    event.is_ua_outdated = true;
    event.detected_browser_version = "Firefox/" + std::to_string(*ver);
  }

  // 4. Platform Inconsistency
  bool has_desktop = ua.find("Windows") != std::string::npos ||
                     ua.find("Macintosh") != std::string::npos ||
                     ua.find("Linux") != std::string::npos;
  bool has_mobile = ua.find("iPhone") != std::string::npos ||
                    ua.find("Android") != std::string::npos;
  if (has_desktop && has_mobile) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "Detected inconsistent UA platform (both mobile and desktop).");
    event.is_ua_inconsistent = true;
  }

  // 5. UA changed and cycling check
  // Prune the cycling window first
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
      "Pruning recent_unique_ua_window for UA cycling check.");
  ip_state.recent_unique_ua_window.prune_old_events(max_ts);

  // Check if UA changed since last request
  if (!ip_state.last_known_user_agent.empty() &&
      ip_state.last_known_user_agent != ua) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "UA changed for IP. Old: '" << ip_state.last_known_user_agent
                                    << "', New: '" << ua << "'");
    event.is_ua_changed_for_ip = true;
  }
  ip_state.last_known_user_agent = ua;

  // Add to cycling window only if it is a new UA for the window
  bool found_in_window = false;
  for (const auto &pair :
       ip_state.recent_unique_ua_window.get_raw_window_data()) {
    if (pair.second == ua) {
      found_in_window = true;
      break;
    }
  }

  if (!found_in_window) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
        "Adding new unique UA to window: " << ua);
    ip_state.recent_unique_ua_window.add_event(ts, ua);
  }
  if (ip_state.recent_unique_ua_window.get_event_count() >
      static_cast<size_t>(cfg.max_unique_uas_per_ip_in_window)) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "UA cycling detected. Unique UAs in window: "
            << ip_state.recent_unique_ua_window.get_event_count());
    event.is_ua_cycling = true;
  }
}

bool AnalysisEngine::save_state(const std::string &path) const {
  LOG(LogLevel::TRACE, LogComponent::STATE_PERSIST,
      "Entering save_state to path: " << path);
  std::string temp_path = path + ".tmp";
  Utils::create_directory_for_file(path);
  std::ofstream out(temp_path, std::ios::binary);
  if (!out) {
    LOG(LogLevel::ERROR, LogComponent::STATE_PERSIST,
        "AnalysisEngine: Could not open temporary state file for writing: "
            << temp_path);
    return false;
  }

  // Write header
  out.write(reinterpret_cast<const char *>(&app_config.state_file_magic),
            sizeof(app_config.state_file_magic));
  out.write(reinterpret_cast<const char *>(&STATE_FILE_VERSION),
            sizeof(STATE_FILE_VERSION));

  // Write IP trackers
  size_t ip_map_size = ip_activity_trackers.size();
  LOG(LogLevel::DEBUG, LogComponent::STATE_PERSIST,
      "Saving " << ip_map_size << " IP states.");
  out.write(reinterpret_cast<const char *>(&ip_map_size), sizeof(ip_map_size));
  for (const auto &pair : ip_activity_trackers) {
    Utils::save_string(out, pair.first);
    pair.second.save(out);
  }

  out.close();

  if (std::rename(temp_path.c_str(), path.c_str()) != 0) {
    LOG(LogLevel::ERROR, LogComponent::STATE_PERSIST,
        "AnalysisEngine: Could not rename temporary state file to final path: "
            << path);
    std::remove(temp_path.c_str());
    return false;
  }

  LOG(LogLevel::INFO, LogComponent::STATE_PERSIST,
      "AnalysisEngine state successfully saved to " << path);
  return true;
}

bool AnalysisEngine::load_state(const std::string &path) {
  LOG(LogLevel::TRACE, LogComponent::STATE_PERSIST,
      "Entering load_state from path: " << path);
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    LOG(LogLevel::INFO, LogComponent::STATE_PERSIST,
        "AnalysisEngine: No state file found at: " << path
                                                   << ". Starting fresh.");
    return false;
  }

  // Read and validate header
  uint32_t magic = 0, version = 0;
  in.read(reinterpret_cast<char *>(&magic), sizeof(magic));
  in.read(reinterpret_cast<char *>(&version), sizeof(version));

  if (magic != app_config.state_file_magic || version != STATE_FILE_VERSION) {
    LOG(LogLevel::WARN, LogComponent::STATE_PERSIST,
        "Warning: State file is incompatible or corrupt. Starting fresh. File "
        "magic/version: "
            << magic << "/" << version);
    return false;
  }

  // Read IP trackers
  size_t ip_map_size = 0;
  in.read(reinterpret_cast<char *>(&ip_map_size), sizeof(ip_map_size));
  LOG(LogLevel::DEBUG, LogComponent::STATE_PERSIST,
      "Loading " << ip_map_size << " IP states.");
  ip_activity_trackers.clear();
  for (size_t i = 0; i < ip_map_size; ++i) {
    std::string ip = Utils::load_string(in);
    PerIpState state;
    state.load(in);
    ip_activity_trackers.emplace(ip, std::move(state));
  }

  // Read Path trackers
  size_t path_map_size = 0;
  in.read(reinterpret_cast<char *>(&path_map_size), sizeof(path_map_size));
  LOG(LogLevel::DEBUG, LogComponent::STATE_PERSIST,
      "Loading " << path_map_size << " Path states.");
  path_activity_trackers.clear();
  for (size_t i = 0; i < path_map_size; ++i) {
    std::string path_str = Utils::load_string(in);
    PerPathState state;
    state.load(in);
    path_activity_trackers.emplace(path_str, std::move(state));
  }

  LOG(LogLevel::INFO, LogComponent::STATE_PERSIST,
      "AnalysisEngine state successfully loaded from " << path);
  return true;
}

uint64_t AnalysisEngine::get_max_timestamp_seen() const {
  return max_timestamp_seen_;
}

void AnalysisEngine::run_pruning(uint64_t current_timestamp_ms) {
  LOG(LogLevel::TRACE, LogComponent::STATE_PRUNE,
      "Entering run_pruning. Current time: " << current_timestamp_ms);
  const uint64_t ttl_ms = app_config.state_ttl_seconds * 1000;
  if (ttl_ms == 0 || !app_config.state_pruning_enabled) {
    LOG(LogLevel::DEBUG, LogComponent::STATE_PRUNE,
        "State pruning is disabled or TTL is 0, skipping.");
    return;
  }

  size_t ips_before = ip_activity_trackers.size();
  for (auto it = ip_activity_trackers.begin();
       it != ip_activity_trackers.end();) {
    if ((current_timestamp_ms - it->second.last_seen_timestamp_ms) > ttl_ms)
      it = ip_activity_trackers.erase(it);
    else
      ++it;
  }
  LOG(LogLevel::DEBUG, LogComponent::STATE_PRUNE,
      "Pruned " << (ips_before - ip_activity_trackers.size()) << " IP states.");

  size_t paths_before = path_activity_trackers.size();
  for (auto it = path_activity_trackers.begin();
       it != path_activity_trackers.end();) {
    if ((current_timestamp_ms - it->second.last_seen_timestamp_ms) > ttl_ms)
      it = path_activity_trackers.erase(it);
    else
      ++it;
  }
  LOG(LogLevel::DEBUG, LogComponent::STATE_PRUNE,
      "Pruned " << (paths_before - path_activity_trackers.size())
                << " Path states.");

  if (app_config.tier1.session_tracking_enabled) {
    size_t sessions_before = session_trackers.size();
    const uint64_t session_ttl_ms =
        app_config.tier1.session_inactivity_ttl_seconds * 1000;
    if (session_ttl_ms > 0)
      for (auto it = session_trackers.begin(); it != session_trackers.end();) {
        if ((current_timestamp_ms - it->second.last_seen_timestamp_ms) >
            session_ttl_ms)
          it = session_trackers.erase(it);
        else
          ++it;
      }
    LOG(LogLevel::DEBUG, LogComponent::STATE_PRUNE,
        "Pruned " << (sessions_before - session_trackers.size())
                  << " Session states.");
  }

  LOG(LogLevel::INFO, LogComponent::STATE_PRUNE, "State pruning completed.");
}

void AnalysisEngine::reset_in_memory_state() {
  ip_activity_trackers.clear();
  path_activity_trackers.clear();
  session_trackers.clear();
  max_timestamp_seen_ = 0;
  LOG(LogLevel::WARN, LogComponent::STATE_PERSIST,
      "AnalysisEngine: In-memory state has been reset.");
}

void AnalysisEngine::reconfigure(const Config::AppConfig &new_config) {
  app_config = new_config;

  uint64_t window_duration_ms =
      app_config.tier1.sliding_window_duration_seconds * 1000;
  LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_LIFECYCLE,
      "Reconfiguring all sliding windows to new duration: "
          << window_duration_ms << "ms");
  for (auto &pair : ip_activity_trackers) {
    pair.second.request_timestamps_window.reconfigure(window_duration_ms, 0);
    pair.second.failed_login_timestamps_window.reconfigure(window_duration_ms,
                                                           0);
    pair.second.html_request_timestamps.reconfigure(window_duration_ms, 0);
    pair.second.asset_request_timestamps.reconfigure(window_duration_ms, 0);
    pair.second.recent_unique_ua_window.reconfigure(window_duration_ms, 0);
  }

  LOG(LogLevel::INFO, LogComponent::ANALYSIS_LIFECYCLE,
      "AnalysisEngine has been reconfigured with new settings.");
}

AnalyzedEvent AnalysisEngine::process_and_analyze(const LogEntry &raw_log) {
  static Histogram *processing_timer =
      MetricsManager::instance().register_histogram(
          "ad_analysis_engine_process_duration_seconds",
          "Latency of the entire AnalysisEngine::process_and_analyze "
          "function.");
  ScopedTimer timer(*processing_timer);
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
      "Entering process_and_analyze for IP: " << raw_log.ip_address << " Path: "
                                              << raw_log.request_path);

  // --- Granular Timers ---
  static Histogram *state_lookup_timer =
      app_config.monitoring.enable_deep_timing
          ? MetricsManager::instance().register_histogram(
                "ad_analysis_state_lookup_duration_seconds",
                "Latency of get_or_create IP/Path state.")
          : nullptr;

  static Histogram *zscore_calc_timer =
      app_config.monitoring.enable_deep_timing
          ? MetricsManager::instance().register_histogram(
                "ad_analysis_zscore_calc_duration_seconds",
                "Latency of Z-Score calculation block.")
          : nullptr;

  static Histogram *ua_analysis_timer =
      app_config.monitoring.enable_deep_timing
          ? MetricsManager::instance().register_histogram(
                "ad_analysis_ua_analysis_duration_seconds",
                "Latency of advanced User-Agent analysis.")
          : nullptr;

  AnalyzedEvent event(raw_log);

  if (!raw_log.parsed_timestamp_ms) {
    LOG(LogLevel::WARN, LogComponent::ANALYSIS_LIFECYCLE,
        "Skipping analysis for log line " << raw_log.original_line_number
                                          << " due to missing timestamp.");
    return event;
  }
  uint64_t current_event_ts = *raw_log.parsed_timestamp_ms;

  if (current_event_ts > max_timestamp_seen_) {
    max_timestamp_seen_ = current_event_ts;
  }

  // --- Instrument State Lookup ---
  PerIpState *current_ip_state_ptr;
  PerPathState *current_path_state_ptr;

  {
    std::optional<ScopedTimer> t =
        state_lookup_timer ? std::optional<ScopedTimer>(*state_lookup_timer)
                           : std::nullopt;
    current_ip_state_ptr = &get_or_create_ip_state(
        std::string(raw_log.ip_address), current_event_ts);
    current_path_state_ptr =
        &get_or_create_path_state(raw_log.request_path, current_event_ts);
  }

  PerIpState &current_ip_state = *current_ip_state_ptr;
  PerPathState &current_path_state = *current_path_state_ptr;

  // --- "New Seen" Tracking Logic ---
  if (current_ip_state.ip_first_seen_timestamp_ms == 0) {
    current_ip_state.ip_first_seen_timestamp_ms = current_event_ts;
    event.is_first_request_from_ip = true;
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "First request ever seen from IP: " << raw_log.ip_address);
  }

  if (current_ip_state.paths_seen_by_ip.find(raw_log.request_path) ==
      current_ip_state.paths_seen_by_ip.end()) {
    event.is_path_new_for_ip = true;
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
        "IP " << raw_log.ip_address
              << " accessed a new path: " << raw_log.request_path);

    // Enforce the cap from the configuration to prevent unbounded memory growth
    const size_t path_cap = app_config.tier1.max_unique_paths_stored_per_ip;
    if (path_cap == 0 || current_ip_state.paths_seen_by_ip.size() < path_cap)
      current_ip_state.paths_seen_by_ip.insert(raw_log.request_path);
    else
      LOG(LogLevel::WARN, LogComponent::ANALYSIS_LIFECYCLE,
          "Paths seen by IP " << raw_log.ip_address
                              << " has reached its cap of " << path_cap
                              << ". Not storing new path.");
  }

  // --- Tier 1 window updates ---
  // Update IP's request timestamp window
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
      "Updating request_timestamps_window for IP: " << raw_log.ip_address);
  current_ip_state.request_timestamps_window.add_event(current_event_ts,
                                                       current_event_ts);
  current_ip_state.request_timestamps_window.prune_old_events(
      max_timestamp_seen_);
  event.current_ip_request_count_in_window =
      current_ip_state.request_timestamps_window.get_event_count();

  // Update IP's failed login window if applicable
  if (raw_log.http_status_code) {
    int status = *raw_log.http_status_code;
    const auto &codes = app_config.tier1.failed_login_status_codes;
    if (std::find(codes.begin(), codes.end(), status) != codes.end()) {
      LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
          "Detected failed login status "
              << status << ". Updating failed_login_timestamps_window for IP: "
              << raw_log.ip_address);
      current_ip_state.failed_login_timestamps_window.add_event(
          current_event_ts, static_cast<uint64_t>(status));
      current_ip_state.failed_login_timestamps_window.prune_old_events(
          max_timestamp_seen_);
    }
  }

  event.current_ip_failed_login_count_in_window =
      current_ip_state.failed_login_timestamps_window.get_event_count();

  // HTML/Asset request tracking
  RequestType type = get_request_type(raw_log.request_path, app_config.tier1);
  if (type == RequestType::HTML) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
        "Request identified as HTML. Updating html_request_timestamps.");
    current_ip_state.html_request_timestamps.add_event(current_event_ts, 1);
    current_ip_state.html_request_timestamps.prune_old_events(
        max_timestamp_seen_);
  } else if (type == RequestType::ASSET) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
        "Request identified as ASSET. Updating asset_request_timestamps.");
    current_ip_state.asset_request_timestamps.add_event(current_event_ts, 1);
    current_ip_state.asset_request_timestamps.prune_old_events(
        max_timestamp_seen_);
  }

  event.ip_html_requests_in_window =
      current_ip_state.html_request_timestamps.get_event_count();
  event.ip_asset_requests_in_window =
      current_ip_state.asset_request_timestamps.get_event_count();

  if (event.ip_html_requests_in_window > 0) {
    event.ip_assets_per_html_ratio =
        static_cast<double>(event.ip_asset_requests_in_window) /
        static_cast<double>(event.ip_html_requests_in_window);
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_WINDOW,
        "Calculated asset/HTML ratio: " << *event.ip_assets_per_html_ratio);
  }

  // --- Session Tracking ---
  if (app_config.tier1.session_tracking_enabled) {
    std::string session_key = build_session_key(raw_log);

    if (!session_key.empty()) {
      auto it = session_trackers.find(session_key);

      if (it == session_trackers.end() ||
          (current_event_ts - it->second.last_seen_timestamp_ms) >
              (app_config.tier1.session_inactivity_ttl_seconds * 1000)) {
        if (it != session_trackers.end()) {
          LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_SESSION,
              "Session " << session_key << " expired. Erasing old state.");
          session_trackers.erase(it);
        }
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_SESSION,
            "Creating new session for key: " << session_key);
        uint64_t window_duration_ms =
            app_config.tier1.sliding_window_duration_seconds * 1000;
        auto result = session_trackers.emplace(
            session_key, PerSessionState(current_event_ts, window_duration_ms));
        it = result.first;
      }

      // Update the session state with the current event's data
      PerSessionState &session = it->second;
      session.last_seen_timestamp_ms = current_event_ts;
      session.request_count++;
      LOG(LogLevel::TRACE, LogComponent::ANALYSIS_SESSION,
          "Updating session " << session_key << ". Request count now "
                              << session.request_count);
      session.unique_paths_visited.insert(raw_log.request_path);
      session.unique_user_agents.insert(std::string(raw_log.user_agent));

      session.request_history.emplace_back(current_event_ts,
                                           raw_log.request_path);
      if (session.request_history.size() > 50)
        session.request_history.pop_front();

      session.http_method_counts[std::string(raw_log.request_method)]++;
      session.request_timestamps_window.add_event(current_event_ts, 1);

      if (raw_log.request_time_s)
        session.request_time_tracker.update(*raw_log.request_time_s);
      if (raw_log.bytes_sent)
        session.bytes_sent_tracker.update(*raw_log.bytes_sent);

      if (raw_log.http_status_code) {
        int status = *raw_log.http_status_code;
        if (status >= 400 && status < 500)
          session.error_4xx_count++;
        if (status >= 500)
          session.error_5xx_count++;
        const auto &codes = app_config.tier1.failed_login_status_codes;
        if (std::find(codes.begin(), codes.end(), status) != codes.end())
          session.failed_login_attempts++;
      }

      // Populate AnalyzedEvent
      event.raw_session_state = it->second;
      event.derived_session_features =
          SessionFeatureExtractor::extract(it->second);
    }
  }

  // --- Tier 2 historical stats updates ---
  if (raw_log.request_time_s) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
        "Updating request_time_tracker for IP "
            << raw_log.ip_address << " with value " << *raw_log.request_time_s);
    current_ip_state.request_time_tracker.update(*raw_log.request_time_s);
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
        "Updating request_time_tracker for Path " << raw_log.request_path
                                                  << " with value "
                                                  << *raw_log.request_time_s);
    current_path_state.request_time_tracker.update(*raw_log.request_time_s);
  }

  if (raw_log.bytes_sent) {
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
        "Updating bytes_sent_tracker for IP "
            << raw_log.ip_address << " with value " << *raw_log.bytes_sent);
    current_ip_state.bytes_sent_tracker.update(
        static_cast<double>(*raw_log.bytes_sent));
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
        "Updating bytes_sent_tracker for Path "
            << raw_log.request_path << " with value " << *raw_log.bytes_sent);
    current_path_state.bytes_sent_tracker.update(
        static_cast<double>(*raw_log.bytes_sent));
  }

  bool is_error =
      (raw_log.http_status_code && *raw_log.http_status_code >= 400 &&
       *raw_log.http_status_code < 600);
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
      "Updating error_rate_tracker for IP "
          << raw_log.ip_address << " with value " << (is_error ? 1.0 : 0.0));
  current_ip_state.error_rate_tracker.update(is_error ? 1.0 : 0.0);
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
      "Updating error_rate_tracker for Path "
          << raw_log.request_path << " with value " << (is_error ? 1.0 : 0.0));
  current_path_state.error_rate_tracker.update(is_error ? 1.0 : 0.0);
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
      "Updating request_volume_tracker for Path " << raw_log.request_path
                                                  << " with value 1.0");
  current_path_state.request_volume_tracker.update(1.0);

  double current_requests_in_gen_window = static_cast<double>(
      current_ip_state.request_timestamps_window.get_event_count());
  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_STATS,
      "Updating requests_in_window_count_tracker for IP "
          << raw_log.ip_address << " with value "
          << current_requests_in_gen_window);
  current_ip_state.requests_in_window_count_tracker.update(
      current_requests_in_gen_window);

  // --- Populate AnalyzedEvent with raw historical stats ---
  event.ip_hist_req_time_mean =
      current_ip_state.request_time_tracker.get_mean();
  event.ip_hist_req_time_stddev =
      current_ip_state.request_time_tracker.get_stddev();
  event.ip_hist_req_time_samples =
      current_ip_state.request_time_tracker.get_count();

  event.ip_hist_bytes_mean = current_ip_state.bytes_sent_tracker.get_mean();
  event.ip_hist_bytes_stddev = current_ip_state.bytes_sent_tracker.get_stddev();
  event.ip_hist_bytes_samples = current_ip_state.bytes_sent_tracker.get_count();

  event.ip_hist_error_rate_mean =
      current_ip_state.error_rate_tracker.get_mean();
  event.ip_hist_error_rate_stddev =
      current_ip_state.error_rate_tracker.get_stddev();
  event.ip_hist_error_rate_samples =
      current_ip_state.error_rate_tracker.get_count();

  event.ip_hist_req_vol_mean =
      current_ip_state.requests_in_window_count_tracker.get_mean();
  event.ip_hist_req_vol_stddev =
      current_ip_state.requests_in_window_count_tracker.get_stddev();
  event.ip_hist_req_vol_samples =
      current_ip_state.requests_in_window_count_tracker.get_count();

  event.path_hist_req_time_mean =
      current_path_state.request_time_tracker.get_mean();
  event.path_hist_req_time_stddev =
      current_path_state.request_time_tracker.get_stddev();

  event.path_hist_bytes_mean = current_path_state.bytes_sent_tracker.get_mean();
  event.path_hist_bytes_stddev =
      current_path_state.bytes_sent_tracker.get_stddev();

  event.path_hist_error_rate_mean =
      current_path_state.error_rate_tracker.get_mean();
  event.path_hist_error_rate_stddev =
      current_path_state.error_rate_tracker.get_stddev();

  // --- Instrument Z-Score Calculation ---

  {
    std::optional<ScopedTimer> t =
        zscore_calc_timer ? std::optional<ScopedTimer>(*zscore_calc_timer)
                          : std::nullopt;

    // --- Z-Score calculation logic ---
    const auto &tier2_cfg = app_config.tier2;
    size_t min_samples = tier2_cfg.min_samples_for_z_score;
    LOG(LogLevel::TRACE, LogComponent::ANALYSIS_ZSCORE,
        "Checking Z-score conditions with min_samples = " << min_samples);

    // Path Req Time Z-score
    if (raw_log.request_time_s &&
        static_cast<size_t>(
            current_path_state.request_time_tracker.get_count()) >=
            min_samples) {
      double stddev = *event.path_hist_req_time_stddev;
      if (stddev > 1e-6) {
        event.path_req_time_zscore =
            (*raw_log.request_time_s - *event.path_hist_req_time_mean) / stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated path_req_time_zscore: " << *event.path_req_time_zscore
                                                << " for Path "
                                                << raw_log.request_path);
      }
    }

    // Path Bytes Sent Z-score
    if (raw_log.bytes_sent &&
        static_cast<size_t>(
            current_path_state.bytes_sent_tracker.get_count()) >= min_samples) {
      double stddev = *event.path_hist_bytes_stddev;
      if (stddev > 1.0) {
        event.path_bytes_sent_zscore =
            (static_cast<double>(*raw_log.bytes_sent) -
             *event.path_hist_bytes_mean) /
            stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated path_bytes_sent_zscore: "
                << *event.path_bytes_sent_zscore << " for Path "
                << raw_log.request_path);
      }
    }

    // Path Error Event Z-score
    if (static_cast<size_t>(
            current_path_state.error_rate_tracker.get_count()) >= min_samples) {
      double current_error_val =
          (raw_log.http_status_code && *raw_log.http_status_code >= 400) ? 1.0
                                                                         : 0.0;
      double stddev = *event.path_hist_error_rate_stddev;
      if (stddev > 0.01) {
        event.path_error_event_zscore =
            (current_error_val - *event.path_hist_error_rate_mean) / stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated path_error_event_zscore: "
                << *event.path_error_event_zscore << " for Path "
                << raw_log.request_path);
      }
    }

    // Req Time Z-score
    if (raw_log.request_time_s &&
        static_cast<size_t>(
            current_ip_state.request_time_tracker.get_count()) >= min_samples) {
      double stddev = current_ip_state.request_time_tracker.get_stddev();
      if (stddev > 1e-6) {
        event.ip_req_time_zscore =
            (*raw_log.request_time_s -
             current_ip_state.request_time_tracker.get_mean()) /
            stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated ip_req_time_zscore: " << *event.ip_req_time_zscore
                                              << " for IP "
                                              << raw_log.ip_address);
      }
    }

    // Bytes Sent Z-score
    if (raw_log.bytes_sent &&
        static_cast<size_t>(current_ip_state.bytes_sent_tracker.get_count()) >=
            min_samples) {
      double stddev = current_ip_state.bytes_sent_tracker.get_stddev();
      if (stddev > 1.0) {
        event.ip_bytes_sent_zscore =
            (static_cast<double>(*raw_log.bytes_sent) -
             current_ip_state.bytes_sent_tracker.get_mean()) /
            stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated ip_bytes_sent_zscore: " << *event.ip_bytes_sent_zscore
                                                << " for IP "
                                                << raw_log.ip_address);
      }
    }

    // Error Event Z-score
    if (static_cast<size_t>(current_ip_state.error_rate_tracker.get_count()) >=
        min_samples) {
      double current_error_val =
          (raw_log.http_status_code && *raw_log.http_status_code >= 400) ? 1.0
                                                                         : 0.0;
      double stddev = current_ip_state.error_rate_tracker.get_stddev();

      if (stddev > 0.01) {
        event.ip_error_event_zscore =
            (current_error_val -
             current_ip_state.error_rate_tracker.get_mean()) /
            stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated ip_error_event_zscore: " << *event.ip_error_event_zscore
                                                 << " for IP "
                                                 << raw_log.ip_address);
      }
    }

    // Request Volume Z-score
    if (static_cast<size_t>(
            current_ip_state.requests_in_window_count_tracker.get_count()) >=
        min_samples) {
      double current_req_vol = static_cast<double>(
          current_ip_state.request_timestamps_window.get_event_count());
      double stddev =
          current_ip_state.requests_in_window_count_tracker.get_stddev();

      if (stddev > 0.5) {
        event.ip_req_vol_zscore =
            (current_req_vol -
             current_ip_state.requests_in_window_count_tracker.get_mean()) /
            stddev;
        LOG(LogLevel::DEBUG, LogComponent::ANALYSIS_ZSCORE,
            "Calculated ip_req_vol_zscore: " << *event.ip_req_vol_zscore
                                             << " for IP "
                                             << raw_log.ip_address);
      }
    }
  }

  // --- Instrument User-Agent analysis ---
  {
    std::optional<ScopedTimer> t =
        ua_analysis_timer ? std::optional<ScopedTimer>(*ua_analysis_timer)
                          : std::nullopt;
    perform_advanced_ua_analysis(std::string(raw_log.user_agent),
                                 app_config.tier1, current_ip_state, event,
                                 current_event_ts, max_timestamp_seen_);
  }

  // --- Feature extraction for ML ---
  if (app_config.tier3.enabled || app_config.ml_data_collection_enabled) {
    LOG(LogLevel::TRACE, LogComponent::ML_FEATURES,
        "Extracting ML features for event.");
    event.feature_vector = feature_manager_.extract_and_normalize(event);
  }

  if (data_collector_ && !event.feature_vector.empty()) {
    LOG(LogLevel::TRACE, LogComponent::ML_FEATURES,
        "Collecting ML feature vector to file.");
    data_collector_->collect_features(event.feature_vector);
  }

  LOG(LogLevel::TRACE, LogComponent::ANALYSIS_LIFECYCLE,
      "Exiting process_and_analyze for IP: " << raw_log.ip_address);
  return event;
}

void PerPathState::save(std::ofstream &out) const {
  request_time_tracker.save(out);
  bytes_sent_tracker.save(out);
  error_rate_tracker.save(out);
  request_volume_tracker.save(out);
  out.write(reinterpret_cast<const char *>(&last_seen_timestamp_ms),
            sizeof(last_seen_timestamp_ms));
}

void PerPathState::load(std::ifstream &in) {
  request_time_tracker.load(in);
  bytes_sent_tracker.load(in);
  error_rate_tracker.load(in);
  request_volume_tracker.load(in);
  in.read(reinterpret_cast<char *>(&last_seen_timestamp_ms),
          sizeof(last_seen_timestamp_ms));
}

void PerIpState::save(std::ofstream &out) const {
  // Tier 1 Windows
  request_timestamps_window.save(out);
  failed_login_timestamps_window.save(out);
  html_request_timestamps.save(out);
  asset_request_timestamps.save(out);
  recent_unique_ua_window.save(out);

  // Timestamps and simple members
  out.write(reinterpret_cast<const char *>(&last_seen_timestamp_ms),
            sizeof(last_seen_timestamp_ms));
  out.write(reinterpret_cast<const char *>(&ip_first_seen_timestamp_ms),
            sizeof(ip_first_seen_timestamp_ms));

  // Unordered sets need special handling
  size_t paths_seen_size = paths_seen_by_ip.size();
  out.write(reinterpret_cast<const char *>(&paths_seen_size),
            sizeof(paths_seen_size));
  for (const auto &path : paths_seen_by_ip) {
    Utils::save_string(out, path);
  }

  Utils::save_string(out, last_known_user_agent);

  // Tier 2 Historical Trackers
  request_time_tracker.save(out);
  bytes_sent_tracker.save(out);
  error_rate_tracker.save(out);
  requests_in_window_count_tracker.save(out);
}

void PerIpState::load(std::ifstream &in) {
  // Tier 1 Windows
  request_timestamps_window.load(in);
  failed_login_timestamps_window.load(in);
  html_request_timestamps.load(in);
  asset_request_timestamps.load(in);
  recent_unique_ua_window.load(in);

  // Timestamps and simple members
  in.read(reinterpret_cast<char *>(&last_seen_timestamp_ms),
          sizeof(last_seen_timestamp_ms));
  in.read(reinterpret_cast<char *>(&ip_first_seen_timestamp_ms),
          sizeof(ip_first_seen_timestamp_ms));

  // Unordered sets
  size_t paths_seen_size = 0;
  in.read(reinterpret_cast<char *>(&paths_seen_size), sizeof(paths_seen_size));
  paths_seen_by_ip.clear();
  for (size_t i = 0; i < paths_seen_size; ++i) {
    paths_seen_by_ip.insert(Utils::load_string(in));
  }

  last_known_user_agent = Utils::load_string(in);

  // Tier 2 Historical Trackers
  request_time_tracker.load(in);
  bytes_sent_tracker.load(in);
  error_rate_tracker.load(in);
  requests_in_window_count_tracker.load(in);
}

std::vector<TopIpInfo>
AnalysisEngine::get_top_n_by_metric(size_t n, const std::string &metric_name) {
  std::vector<TopIpInfo> all_ips;
  {
    // Must lock to safely read from the map
    // This is a simplified example. In a real high-throughput system,
    // you might copy the data or use more advanced concurrent structures.
    // For now, a lock is sufficient and safe.
    // NOTE: This lock can introduce latency on the main processing thread if
    // held for long.
    all_ips.reserve(ip_activity_trackers.size());
    for (const auto &[ip, state] : ip_activity_trackers) {
      double value = 0.0;
      if (metric_name == "request_rate") {
        value = state.request_timestamps_window.get_event_count();
      } else if (metric_name == "error_rate") {
        value = state.error_rate_tracker.get_mean();
      }
      // More metrics can be added here

      all_ips.push_back({ip, value, metric_name});
    }
  }

  std::vector<TopIpInfo> top_n;
  top_n.reserve(n);

  // Sort all IPs and take the top n
  std::sort(all_ips.begin(), all_ips.end(),
            [](const TopIpInfo &a, const TopIpInfo &b) {
              return a.value > b.value; // Sort descending
            });

  // Take only the top n elements
  size_t limit = std::min(n, all_ips.size());
  top_n.assign(all_ips.begin(), all_ips.begin() + limit);

  return top_n;
}

EngineStateMetrics AnalysisEngine::get_internal_state_metrics() const {
  EngineStateMetrics metrics;

  // This method is read-only, but if the engine were multi-threaded,
  // we would need to acquire a read-lock here to safely iterate the maps.

  metrics.total_ip_states = ip_activity_trackers.size();
  for (const auto &[ip, state] : ip_activity_trackers) {
    metrics.total_ip_asset_req_window_elements +=
        state.get_asset_request_timestamps_count();
    metrics.total_ip_failed_login_window_elements +=
        state.get_failed_login_timestamps_count();
    metrics.total_ip_html_req_window_elements +=
        state.get_html_request_timestamps_count();
    metrics.total_ip_asset_req_window_elements +=
        state.get_asset_request_timestamps_count();
    metrics.total_ip_ua_window_elements += state.get_recent_unique_ua_count();
    metrics.total_ip_paths_seen_elements += state.get_paths_seen_count();
    metrics.total_ip_historical_ua_elements +=
        state.get_historical_user_agents_count();
  }

  metrics.total_path_states = path_activity_trackers.size();

  metrics.total_session_states = session_trackers.size();
  for (const auto &[key, state] : session_trackers) {
    metrics.total_session_req_window_elements +=
        state.get_request_timestamps_count();
    metrics.total_session_unique_paths += state.get_unique_paths_count();
    metrics.total_session_unique_user_agents +=
        state.get_unique_user_agents_count();
  }

  return metrics;
}