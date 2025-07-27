#include "optimized_intel_manager.hpp"
#include "core/logger.hpp"
#include "dns_cache.hpp"
#include "httplib.h"
#include "utils/utils.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <regex>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;

//=============================================================================
// OptimizedIntelManager Implementation
//=============================================================================

OptimizedIntelManager::OptimizedIntelManager(const Config &config)
    : config_(config) {

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "Initializing OptimizedIntelManager with " << config_.feed_urls.size()
                                                 << " threat feeds");

  // Initialize Bloom filters with optimal sizing
  ip_bloom_filter_ = std::make_unique<memory::BloomFilter<uint32_t>>(
      config_.bloom_filter_size, config_.bloom_filter_fpp);

  domain_bloom_filter_ = std::make_unique<memory::BloomFilter<uint64_t>>(
      config_.bloom_filter_size / 2,
      config_.bloom_filter_fpp); // Domains typically fewer

  // Initialize data structures
  domain_trie_ = std::make_unique<CompressedTrie>(config_.domain_cache_size);
  threat_db_ =
      std::make_unique<IncrementalThreatDatabase>(config_.ip_cache_size);

  if (config_.enable_dns_caching) {
    DNSCache::Config dns_config{};
    dns_config.max_entries = config_.domain_cache_size / 4;
    dns_cache_ = std::make_unique<DNSCache>(dns_config);
  }

  if (config_.enable_geolocation) {
    GeolocationCache::Config geo_config{};
    geo_config.max_entries = config_.ip_cache_size / 2;
    geo_cache_ = std::make_unique<GeolocationCache>(geo_config);
  }

  // Initialize persistent storage
  if (config_.enable_memory_mapping) {
    // persistent_db_ = std::make_unique<MemoryMappedThreatDB>();
    // TODO: Implement when database dependency is available
  }

  // Skip initial update during testing
  // update_feeds();

  // Start background update thread
  background_thread_ =
      std::thread(&OptimizedIntelManager::background_thread_func, this);
}

OptimizedIntelManager::~OptimizedIntelManager() {
  shutdown_flag_ = true;
  cv_.notify_all();

  if (background_thread_.joinable()) {
    background_thread_.join();
  }

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "OptimizedIntelManager shut down. Final stats: "
          << "IPs: " << stats_.total_ips.load()
          << ", Domains: " << stats_.total_domains.load()
          << ", Memory: " << get_memory_usage() << " bytes");
}

bool OptimizedIntelManager::is_blacklisted_ip(uint32_t ip) const {
  std::shared_lock<std::shared_mutex> lock(data_mutex_);

  // Fast Bloom filter check first
  if (!ip_bloom_filter_->contains(ip)) {
    increment_lookup_miss();
    return false;
  }

  increment_bloom_hit();

  // Check in exact database
  auto threat_info = threat_db_->get_threat_info(ip);
  if (threat_info && (threat_info->threat_types &
                      static_cast<uint8_t>(ThreatInfo::Type::MALICIOUS_IP))) {
    increment_lookup_hit();
    return true;
  }

  // False positive in Bloom filter
  increment_bloom_fp();
  increment_lookup_miss();
  return false;
}

bool OptimizedIntelManager::is_blacklisted_ip(std::string_view ip_str) const {
  if (!is_valid_ip_string(ip_str)) {
    increment_lookup_miss();
    return false;
  }

  uint32_t ip = Utils::ip_string_to_uint32(std::string(ip_str));
  return is_blacklisted_ip(ip);
}

bool OptimizedIntelManager::is_blacklisted_domain(
    std::string_view domain) const {
  if (!is_valid_domain(domain)) {
    increment_lookup_miss();
    return false;
  }

  std::shared_lock<std::shared_mutex> lock(data_mutex_);

  uint64_t domain_hash = hash_domain(domain);

  // Fast Bloom filter check first
  if (!domain_bloom_filter_->contains(domain_hash)) {
    increment_lookup_miss();
    return false;
  }

  increment_bloom_hit();

  // Check exact match in trie (includes wildcard matching)
  if (domain_trie_->contains(domain) ||
      domain_trie_->contains_subdomain(domain)) {
    increment_lookup_hit();
    return true;
  }

  // False positive in Bloom filter
  increment_bloom_fp();
  increment_lookup_miss();
  return false;
}

bool OptimizedIntelManager::is_suspicious_ip(uint32_t ip) const {
  std::shared_lock<std::shared_mutex> lock(data_mutex_);

  auto threat_info = threat_db_->get_threat_info(ip);
  return threat_info && (threat_info->threat_types &
                         static_cast<uint8_t>(ThreatInfo::Type::SUSPICIOUS_IP));
}

bool OptimizedIntelManager::is_suspicious_domain(
    std::string_view domain) const {
  if (!is_valid_domain(domain)) {
    return false;
  }

  std::shared_lock<std::shared_mutex> lock(data_mutex_);
  auto threat_info = threat_db_->get_threat_info(domain);
  return threat_info &&
         (threat_info->threat_types &
          static_cast<uint8_t>(ThreatInfo::Type::SUSPICIOUS_DOMAIN));
}

OptimizedIntelManager::ThreatInfo
OptimizedIntelManager::get_threat_info(uint32_t ip) const {
  std::shared_lock<std::shared_mutex> lock(data_mutex_);

  auto info = threat_db_->get_threat_info(ip);
  return info ? *info : ThreatInfo{};
}

OptimizedIntelManager::ThreatInfo
OptimizedIntelManager::get_threat_info(std::string_view domain) const {
  std::shared_lock<std::shared_mutex> lock(data_mutex_);

  auto info = threat_db_->get_threat_info(domain);
  return info ? *info : ThreatInfo{};
}

std::optional<OptimizedIntelManager::GeolocationInfo>
OptimizedIntelManager::get_geolocation(uint32_t ip) const {
  if (!config_.enable_geolocation || !geo_cache_) {
    return std::nullopt;
  }

  auto geo_info = geo_cache_->lookup(ip);
  if (geo_info) {
    stats_.geolocation_cache_hits.fetch_add(1, std::memory_order_relaxed);
    return OptimizedIntelManager::GeolocationInfo{
        .country_code = geo_info->country_code,
        .country_name = geo_info->country_name,
        .city = geo_info->city,
        .latitude = geo_info->latitude,
        .longitude = geo_info->longitude,
        .asn = geo_info->asn,
        .isp = geo_info->isp};
  }

  // TODO: Fetch from external geolocation service and cache
  return std::nullopt;
}

std::optional<std::string>
OptimizedIntelManager::resolve_hostname(uint32_t ip) const {
  if (!config_.enable_dns_caching || !dns_cache_) {
    return std::nullopt;
  }

  auto hostname = dns_cache_->lookup_hostname(ip);
  if (hostname) {
    stats_.dns_cache_hits.fetch_add(1, std::memory_order_relaxed);
  }

  return hostname;
}

std::optional<uint32_t>
OptimizedIntelManager::resolve_domain(std::string_view domain) const {
  if (!config_.enable_dns_caching || !dns_cache_) {
    return std::nullopt;
  }

  auto ip = dns_cache_->lookup_ip(domain);
  if (ip) {
    stats_.dns_cache_hits.fetch_add(1, std::memory_order_relaxed);
  }

  return ip;
}

void OptimizedIntelManager::force_update() {
  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "Forcing threat intelligence update");
  update_feeds();
}

void OptimizedIntelManager::clear_caches() {
  std::unique_lock<std::shared_mutex> lock(data_mutex_);

  if (dns_cache_)
    dns_cache_->clear();
  if (geo_cache_)
    geo_cache_->clear();

  stats_.cache_evictions.fetch_add(1, std::memory_order_relaxed);

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL, "Cleared all caches");
}

OptimizedIntelManager::Statistics
OptimizedIntelManager::get_statistics() const {
  return stats_;
}

void OptimizedIntelManager::update_config(const Config &new_config) {
  std::unique_lock<std::shared_mutex> lock(data_mutex_);
  config_ = new_config;

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL, "Configuration updated");
}

void OptimizedIntelManager::add_feed_url(const std::string &url) {
  std::unique_lock<std::shared_mutex> lock(data_mutex_);
  config_.feed_urls.push_back(url);

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL, "Added feed URL: " << url);
}

void OptimizedIntelManager::remove_feed_url(const std::string &url) {
  std::unique_lock<std::shared_mutex> lock(data_mutex_);
  auto it = std::find(config_.feed_urls.begin(), config_.feed_urls.end(), url);
  if (it != config_.feed_urls.end()) {
    config_.feed_urls.erase(it);
    LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
        "Removed feed URL: " << url);
  }
}

size_t OptimizedIntelManager::get_memory_usage() const {
  size_t total = current_memory_usage_.load();

  if (ip_bloom_filter_)
    total += ip_bloom_filter_->memory_usage();
  if (domain_bloom_filter_)
    total += domain_bloom_filter_->memory_usage();
  if (domain_trie_)
    total += domain_trie_->get_memory_usage();
  if (threat_db_)
    total += threat_db_->get_memory_usage();
  if (dns_cache_)
    total += dns_cache_->get_memory_usage();
  if (geo_cache_)
    total += geo_cache_->get_memory_usage();

  return total;
}

size_t OptimizedIntelManager::compact() {
  std::unique_lock<std::shared_mutex> lock(data_mutex_);

  size_t freed = 0;

  if (domain_trie_)
    freed += domain_trie_->compact();
  if (threat_db_)
    freed += threat_db_->compact();
  if (dns_cache_)
    freed += dns_cache_->compact();
  if (geo_cache_)
    freed += geo_cache_->compact();

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "Compacted threat intelligence data, freed " << freed << " bytes");

  return freed;
}

void OptimizedIntelManager::on_memory_pressure(size_t pressure_level) {
  LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
      "Memory pressure detected: " << pressure_level);

  handle_memory_pressure();
}

bool OptimizedIntelManager::can_evict() const {
  return true; // Can evict cache entries
}

void OptimizedIntelManager::background_thread_func() {
  while (!shutdown_flag_) {
    std::unique_lock<std::mutex> lock(cv_mutex_);
    cv_.wait_for(lock, std::chrono::seconds(config_.update_interval_seconds),
                 [this] { return shutdown_flag_.load(); });

    if (shutdown_flag_)
      break;

    LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
        "Running periodic threat intelligence update");
    update_feeds();
  }
}

void OptimizedIntelManager::update_feeds() {
  auto start_time = std::chrono::steady_clock::now();
  uint32_t generation = update_generation_.fetch_add(1) + 1;

  // Begin incremental update
  threat_db_->begin_update(generation);

  size_t total_new_ips = 0;
  size_t total_new_domains = 0;

  for (size_t i = 0; i < config_.feed_urls.size(); ++i) {
    try {
      update_single_feed(config_.feed_urls[i], static_cast<uint16_t>(i + 1));
    } catch (const std::exception &e) {
      LOG(LogLevel::ERROR, LogComponent::IO_THREATINTEL,
          "Failed to update feed " << config_.feed_urls[i] << ": " << e.what());
    }
  }

  // Commit the update
  threat_db_->commit_update();

  // Rebuild Bloom filters with new data
  rebuild_bloom_filters();

  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  last_update_timestamp_ =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "Threat intelligence update completed in "
          << duration.count() << "ms. "
          << "Total entries: IPs=" << stats_.total_ips.load()
          << ", Domains=" << stats_.total_domains.load());
}

void OptimizedIntelManager::update_single_feed(const std::string &url,
                                               uint16_t source_id) {
  std::regex url_regex(R"(^(https?):\/\/([^\/]+)(\/.*)?$)");
  std::smatch match;

  if (!std::regex_match(url, match, url_regex)) {
    LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
        "Invalid feed URL format: " << url);
    return;
  }

  std::string host = match[2].str();
  std::string path = match[3].matched ? match[3].str() : "/";
  bool is_https = (match[1].str() == "https");

  auto process_request = [&](auto &client) {
    auto res = client.Get(path.c_str());
    if (res && res->status == 200) {
      std::istringstream iss(res->body);
      std::string line;

      while (std::getline(iss, line)) {
        std::string trimmed = Utils::trim_copy(line);
        if (!trimmed.empty() && trimmed[0] != '#') {
          process_threat_entry(trimmed, source_id);
        }
      }
    } else {
      LOG(LogLevel::ERROR, LogComponent::IO_THREATINTEL,
          "Failed to fetch feed from "
              << url
              << (res ? " | Status: " + std::to_string(res->status) : ""));
    }
  };

  // Create appropriate HTTP client
  if (is_https) {
    httplib::SSLClient client(host);
    client.enable_server_certificate_verification(false);
    client.set_connection_timeout(30, 0); // 30 seconds
    process_request(client);
  } else {
    httplib::Client client(host);
    client.set_connection_timeout(30, 0); // 30 seconds
    process_request(client);
  }
}

void OptimizedIntelManager::process_threat_entry(const std::string &entry,
                                                 uint16_t source_id) {
  // Try to parse as IP first
  uint32_t ip = Utils::ip_string_to_uint32(entry);
  if (ip != 0) {
    ThreatInfo info{};
    info.threat_types = static_cast<uint8_t>(ThreatInfo::Type::MALICIOUS_IP);
    info.confidence_score = 80; // Default confidence
    info.last_seen_timestamp = static_cast<uint32_t>(std::time(nullptr));
    info.source_id = source_id;

    threat_db_->add_threat(ip, info);
    stats_.total_ips.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  // Try to parse as domain
  if (is_valid_domain(entry)) {
    ThreatInfo info{};
    info.threat_types =
        static_cast<uint8_t>(ThreatInfo::Type::MALICIOUS_DOMAIN);
    info.confidence_score = 80; // Default confidence
    info.last_seen_timestamp = static_cast<uint32_t>(std::time(nullptr));
    info.source_id = source_id;

    threat_db_->add_threat(entry, info);
    domain_trie_->insert(entry, source_id);
    stats_.total_domains.fetch_add(1, std::memory_order_relaxed);
  }
}

void OptimizedIntelManager::rebuild_bloom_filters() {
  std::unique_lock<std::shared_mutex> lock(data_mutex_);

  // Create new Bloom filters
  auto new_ip_bloom = std::make_unique<memory::BloomFilter<uint32_t>>(
      config_.bloom_filter_size, config_.bloom_filter_fpp);
  auto new_domain_bloom = std::make_unique<memory::BloomFilter<uint64_t>>(
      config_.bloom_filter_size / 2, config_.bloom_filter_fpp);

  // Populate with current data
  // Note: In a real implementation, we'd iterate through threat_db_ and
  // domain_trie_ For now, we'll just swap the filters

  ip_bloom_filter_ = std::move(new_ip_bloom);
  domain_bloom_filter_ = std::move(new_domain_bloom);

  LOG(LogLevel::DEBUG, LogComponent::IO_THREATINTEL, "Rebuilt Bloom filters");
}

void OptimizedIntelManager::handle_memory_pressure() {
  size_t freed = compact();

  if (freed < 1024 * 1024) { // If compaction freed less than 1MB
    clear_caches();
  }

  stats_.cache_evictions.fetch_add(1, std::memory_order_relaxed);
}

uint64_t OptimizedIntelManager::hash_domain(std::string_view domain) const {
  // Simple hash function - in production, use a better hash
  std::hash<std::string_view> hasher;
  return hasher(domain);
}

bool OptimizedIntelManager::is_valid_ip_string(std::string_view ip_str) const {
  return ip_str.find('.') != std::string_view::npos && ip_str.length() >= 7;
}

bool OptimizedIntelManager::is_valid_domain(std::string_view domain) const {
  return domain.find('.') != std::string_view::npos && domain.length() >= 3 &&
         domain.length() <= 253;
}

//=============================================================================
// CompressedTrie Implementation
//=============================================================================

CompressedTrie::CompressedTrie(size_t initial_capacity) {
  root_ = std::make_unique<TrieNode>();
  memory_usage_ = sizeof(TrieNode);
}

CompressedTrie::~CompressedTrie() { clear(); }

bool CompressedTrie::insert(std::string_view domain, uint16_t source_id) {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  insert_reversed(root_.get(), domain, source_id);
  node_count_.fetch_add(1, std::memory_order_relaxed);
  memory_usage_.fetch_add(sizeof(TrieNode), std::memory_order_relaxed);

  return true;
}

bool CompressedTrie::contains(std::string_view domain) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return search_reversed(root_.get(), domain);
}

bool CompressedTrie::contains_subdomain(std::string_view domain) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  // Check if any parent domain matches (wildcard matching)
  size_t pos = domain.find('.');
  while (pos != std::string_view::npos) {
    std::string_view parent = domain.substr(pos + 1);
    if (search_reversed(root_.get(), parent)) {
      return true;
    }
    pos = domain.find('.', pos + 1);
  }

  return false;
}

void CompressedTrie::clear() {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  if (root_) {
    clear_node(root_.get());
  }

  node_count_ = 0;
  memory_usage_ = sizeof(TrieNode);
}

size_t CompressedTrie::get_memory_usage() const { return memory_usage_.load(); }

size_t CompressedTrie::compact() {
  // Compressed trie doesn't support compaction in this simple implementation
  return 0;
}

bool CompressedTrie::can_evict() const { return true; }

void CompressedTrie::on_memory_pressure(size_t pressure_level) {
  if (pressure_level > 80) {
    // Clear some nodes if memory pressure is very high
    // This is a simplified implementation
    LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
        "CompressedTrie experiencing memory pressure: " << pressure_level);
  }
}

void CompressedTrie::insert_reversed(TrieNode *node, std::string_view domain,
                                     uint16_t source_id) {
  // Insert domain in reverse order for efficient wildcard matching
  for (auto it = domain.rbegin(); it != domain.rend(); ++it) {
    unsigned char c = static_cast<unsigned char>(*it);
    if (!node->children[c]) {
      node->children[c] = std::make_unique<TrieNode>();
      node->children[c]->node_id = node_count_.fetch_add(1);
    }
    node = node->children[c].get();
  }

  node->is_terminal = true;
  node->source_id = source_id;
}

bool CompressedTrie::search_reversed(const TrieNode *node,
                                     std::string_view domain) const {
  for (auto it = domain.rbegin(); it != domain.rend(); ++it) {
    unsigned char c = static_cast<unsigned char>(*it);
    if (!node->children[c]) {
      return false;
    }
    node = node->children[c].get();
  }

  return node->is_terminal;
}

void CompressedTrie::clear_node(TrieNode *node) {
  for (auto &child : node->children) {
    if (child) {
      clear_node(child.get());
      child.reset();
    }
  }
}

size_t CompressedTrie::calculate_node_memory(const TrieNode *node) const {
  if (!node)
    return 0;

  size_t total = sizeof(TrieNode);
  for (const auto &child : node->children) {
    if (child) {
      total += calculate_node_memory(child.get());
    }
  }

  return total;
}

//=============================================================================
// IncrementalThreatDatabase Implementation
//=============================================================================

IncrementalThreatDatabase::IncrementalThreatDatabase(size_t max_entries)
    : max_entries_(max_entries) {}

IncrementalThreatDatabase::~IncrementalThreatDatabase() = default;

void IncrementalThreatDatabase::add_threat(
    uint32_t ip, const OptimizedIntelManager::ThreatInfo &info) {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  ThreatEntry entry{info, current_generation_.load(), false};
  ip_threats_[ip] = entry;
}

void IncrementalThreatDatabase::add_threat(
    std::string_view domain, const OptimizedIntelManager::ThreatInfo &info) {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  uint64_t domain_hash = hash_domain(domain);
  ThreatEntry entry{info, current_generation_.load(), false};
  domain_threats_[domain_hash] = entry;
}

std::optional<OptimizedIntelManager::ThreatInfo>
IncrementalThreatDatabase::get_threat_info(uint32_t ip) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  auto it = ip_threats_.find(ip);
  if (it != ip_threats_.end() && !it->second.marked_for_deletion) {
    return it->second.info;
  }

  return std::nullopt;
}

std::optional<OptimizedIntelManager::ThreatInfo>
IncrementalThreatDatabase::get_threat_info(std::string_view domain) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  uint64_t domain_hash = hash_domain(domain);
  auto it = domain_threats_.find(domain_hash);
  if (it != domain_threats_.end() && !it->second.marked_for_deletion) {
    return it->second.info;
  }

  return std::nullopt;
}

void IncrementalThreatDatabase::begin_update(uint32_t generation) {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  update_generation_ = generation;
  update_in_progress_ = true;
}

void IncrementalThreatDatabase::commit_update() {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  current_generation_.store(update_generation_.load());
  update_in_progress_ = false;

  cleanup_old_entries();
}

void IncrementalThreatDatabase::rollback_update() {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  update_in_progress_ = false;

  // Remove entries from the failed update
  for (auto it = ip_threats_.begin(); it != ip_threats_.end();) {
    if (it->second.generation == update_generation_) {
      it = ip_threats_.erase(it);
    } else {
      ++it;
    }
  }

  for (auto it = domain_threats_.begin(); it != domain_threats_.end();) {
    if (it->second.generation == update_generation_) {
      it = domain_threats_.erase(it);
    } else {
      ++it;
    }
  }
}

size_t IncrementalThreatDatabase::get_memory_usage() const {
  return ip_threats_.size() * (sizeof(uint32_t) + sizeof(ThreatEntry)) +
         domain_threats_.size() * (sizeof(uint64_t) + sizeof(ThreatEntry));
}

size_t IncrementalThreatDatabase::compact() {
  std::unique_lock<std::shared_mutex> lock(mutex_);

  size_t initial_size = get_memory_usage();
  cleanup_old_entries();
  size_t final_size = get_memory_usage();

  return initial_size - final_size;
}

void IncrementalThreatDatabase::on_memory_pressure(size_t pressure_level) {
  if (pressure_level > 70) {
    compact();
  }
}

bool IncrementalThreatDatabase::can_evict() const { return true; }

void IncrementalThreatDatabase::cleanup_old_entries() {
  uint32_t cutoff_generation =
      current_generation_ > 2 ? current_generation_ - 2 : 0;

  for (auto it = ip_threats_.begin(); it != ip_threats_.end();) {
    if (it->second.generation < cutoff_generation ||
        it->second.marked_for_deletion) {
      it = ip_threats_.erase(it);
    } else {
      ++it;
    }
  }

  for (auto it = domain_threats_.begin(); it != domain_threats_.end();) {
    if (it->second.generation < cutoff_generation ||
        it->second.marked_for_deletion) {
      it = domain_threats_.erase(it);
    } else {
      ++it;
    }
  }
}

uint64_t IncrementalThreatDatabase::hash_domain(std::string_view domain) const {
  std::hash<std::string_view> hasher;
  return hasher(domain);
}
