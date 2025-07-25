#include "dns_cache.hpp"
#include "core/logger.hpp"
#include <algorithm>
#include <chrono>

//=============================================================================
// DNSCache Implementation
//=============================================================================

DNSCache::DNSCache(const Config &config) : config_(config) {
  forward_cache_.reserve(config_.max_entries / 2);
  reverse_cache_.reserve(config_.max_entries / 2);

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "DNSCache initialized with max_entries=" << config_.max_entries);
}

DNSCache::~DNSCache() {
  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "DNSCache destroyed. Final stats: "
          << "Forward hits=" << stats_.forward_hits.load()
          << ", Reverse hits=" << stats_.reverse_hits.load());
}

std::optional<uint32_t> DNSCache::lookup_ip(std::string_view hostname) {
  std::shared_lock<std::shared_mutex> lock(cache_mutex_);

  uint64_t hostname_hash = hash_hostname(hostname);
  auto it = forward_cache_.find(hostname_hash);

  if (it != forward_cache_.end()) {
    // Check if entry is still valid
    if (it->second.expiry_time > std::chrono::steady_clock::now()) {
      if (it->second.is_valid) {
        stats_.forward_hits.fetch_add(1, std::memory_order_relaxed);
        return it->second.ip;
      } else {
        // Negative cache hit (failed lookup cached)
        stats_.forward_hits.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
      }
    } else {
      // Entry expired
      stats_.expired_entries.fetch_add(1, std::memory_order_relaxed);
    }
  }

  stats_.forward_misses.fetch_add(1, std::memory_order_relaxed);
  return std::nullopt;
}

void DNSCache::cache_ip(std::string_view hostname, uint32_t ip,
                        std::chrono::seconds ttl) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  std::chrono::seconds actual_ttl = get_ttl(ttl);
  uint64_t hostname_hash = hash_hostname(hostname);

  ReverseEntry entry{.ip = ip,
                     .expiry_time =
                         std::chrono::steady_clock::now() + actual_ttl,
                     .is_valid = true};

  forward_cache_[hostname_hash] = entry;

  // Check if we need to evict entries
  if (forward_cache_.size() > config_.max_entries / 2) {
    evict_lru_entries(config_.max_entries / 4);
  }

  update_memory_usage();
}

void DNSCache::cache_negative_ip(std::string_view hostname) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  uint64_t hostname_hash = hash_hostname(hostname);

  ReverseEntry entry{.ip = 0,
                     .expiry_time = std::chrono::steady_clock::now() +
                                    config_.negative_ttl,
                     .is_valid = false};

  forward_cache_[hostname_hash] = entry;
  update_memory_usage();
}

std::optional<std::string> DNSCache::lookup_hostname(uint32_t ip) {
  std::shared_lock<std::shared_mutex> lock(cache_mutex_);

  auto it = reverse_cache_.find(ip);

  if (it != reverse_cache_.end()) {
    // Check if entry is still valid
    if (it->second.expiry_time > std::chrono::steady_clock::now()) {
      if (it->second.is_valid) {
        stats_.reverse_hits.fetch_add(1, std::memory_order_relaxed);
        return it->second.hostname;
      } else {
        // Negative cache hit
        stats_.reverse_hits.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
      }
    } else {
      stats_.expired_entries.fetch_add(1, std::memory_order_relaxed);
    }
  }

  stats_.reverse_misses.fetch_add(1, std::memory_order_relaxed);
  return std::nullopt;
}

void DNSCache::cache_hostname(uint32_t ip, std::string_view hostname,
                              std::chrono::seconds ttl) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  std::chrono::seconds actual_ttl = get_ttl(ttl);

  CacheEntry entry{.hostname = std::string(hostname),
                   .expiry_time = std::chrono::steady_clock::now() + actual_ttl,
                   .is_valid = true};

  reverse_cache_[ip] = std::move(entry);

  // Check if we need to evict entries
  if (reverse_cache_.size() > config_.max_entries / 2) {
    evict_lru_entries(config_.max_entries / 4);
  }

  update_memory_usage();
}

void DNSCache::cache_negative_hostname(uint32_t ip) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  CacheEntry entry{.hostname = "",
                   .expiry_time =
                       std::chrono::steady_clock::now() + config_.negative_ttl,
                   .is_valid = false};

  reverse_cache_[ip] = std::move(entry);
  update_memory_usage();
}

void DNSCache::clear() {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  forward_cache_.clear();
  reverse_cache_.clear();
  current_memory_usage_ = 0;

  LOG(LogLevel::DEBUG, LogComponent::IO_THREATINTEL, "DNSCache cleared");
}

void DNSCache::cleanup_expired() {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  auto now = std::chrono::steady_clock::now();
  size_t removed = 0;

  // Clean forward cache
  for (auto it = forward_cache_.begin(); it != forward_cache_.end();) {
    if (it->second.expiry_time <= now) {
      it = forward_cache_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  // Clean reverse cache
  for (auto it = reverse_cache_.begin(); it != reverse_cache_.end();) {
    if (it->second.expiry_time <= now) {
      it = reverse_cache_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  if (removed > 0) {
    stats_.expired_entries.fetch_add(removed, std::memory_order_relaxed);
    update_memory_usage();

    LOG(LogLevel::DEBUG, LogComponent::IO_THREATINTEL,
        "Cleaned up " << removed << " expired DNS entries");
  }
}

size_t DNSCache::get_entry_count() const {
  std::shared_lock<std::shared_mutex> lock(cache_mutex_);
  return forward_cache_.size() + reverse_cache_.size();
}

size_t DNSCache::get_memory_usage() const {
  return current_memory_usage_.load();
}

size_t DNSCache::compact() {
  size_t initial_memory = get_memory_usage();
  cleanup_expired();
  size_t final_memory = get_memory_usage();

  return initial_memory - final_memory;
}

void DNSCache::on_memory_pressure(size_t pressure_level) {
  if (pressure_level > 70) {
    // Aggressive cleanup under high memory pressure
    size_t target_reduction = get_entry_count() / 4; // Remove 25% of entries
    evict_lru_entries(target_reduction);

    LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
        "DNSCache evicted entries due to memory pressure: " << pressure_level);
  }
}

uint64_t DNSCache::hash_hostname(std::string_view hostname) const {
  std::hash<std::string_view> hasher;
  return hasher(hostname);
}

void DNSCache::evict_lru_entries(size_t target_count) {
  // Simple eviction strategy - remove oldest entries first
  // In a production implementation, this would maintain proper LRU order

  size_t removed = 0;
  auto now = std::chrono::steady_clock::now();

  // Remove entries that are close to expiry first
  for (auto it = forward_cache_.begin();
       it != forward_cache_.end() && removed < target_count;) {
    if (it->second.expiry_time - now < std::chrono::minutes(5)) {
      it = forward_cache_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  for (auto it = reverse_cache_.begin();
       it != reverse_cache_.end() && removed < target_count;) {
    if (it->second.expiry_time - now < std::chrono::minutes(5)) {
      it = reverse_cache_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  if (removed > 0) {
    stats_.evicted_entries.fetch_add(removed, std::memory_order_relaxed);
    update_memory_usage();
  }
}

void DNSCache::update_memory_usage() {
  size_t total = 0;

  // Estimate memory usage
  total += forward_cache_.size() * (sizeof(uint64_t) + sizeof(ReverseEntry));

  for (const auto &entry : reverse_cache_) {
    total +=
        sizeof(uint32_t) + sizeof(CacheEntry) + entry.second.hostname.size();
  }

  current_memory_usage_ = total;
}

std::chrono::seconds
DNSCache::get_ttl(std::chrono::seconds requested_ttl) const {
  return requested_ttl.count() > 0 ? requested_ttl : config_.default_ttl;
}

//=============================================================================
// GeolocationCache Implementation
//=============================================================================

GeolocationCache::GeolocationCache(const Config &config) : config_(config) {
  cache_.reserve(config_.max_entries);

  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "GeolocationCache initialized with max_entries=" << config_.max_entries);
}

GeolocationCache::~GeolocationCache() {
  LOG(LogLevel::INFO, LogComponent::IO_THREATINTEL,
      "GeolocationCache destroyed. Final stats: "
          << "Hits=" << stats_.hits.load()
          << ", Misses=" << stats_.misses.load());
}

std::optional<GeolocationCache::GeolocationInfo>
GeolocationCache::lookup(uint32_t ip) {
  std::shared_lock<std::shared_mutex> lock(cache_mutex_);

  auto it = cache_.find(ip);

  if (it != cache_.end()) {
    // Check if entry is still valid
    if (it->second.expiry_time > std::chrono::steady_clock::now()) {
      if (it->second.is_valid) {
        stats_.hits.fetch_add(1, std::memory_order_relaxed);
        return it->second.info;
      } else {
        // Negative cache hit
        stats_.hits.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
      }
    } else {
      stats_.expired_entries.fetch_add(1, std::memory_order_relaxed);
    }
  }

  stats_.misses.fetch_add(1, std::memory_order_relaxed);
  return std::nullopt;
}

void GeolocationCache::cache_location(uint32_t ip, const GeolocationInfo &info,
                                      std::chrono::seconds ttl) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  std::chrono::seconds actual_ttl = get_ttl(ttl);

  CacheEntry entry{.info = info,
                   .expiry_time = std::chrono::steady_clock::now() + actual_ttl,
                   .is_valid = true};

  // Compact strings to save memory
  entry.info.compact();

  cache_[ip] = std::move(entry);

  // Check if we need to evict entries
  if (cache_.size() > config_.max_entries) {
    evict_lru_entries(config_.max_entries / 10); // Remove 10%
  }

  update_memory_usage();
}

void GeolocationCache::cache_negative(uint32_t ip) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  CacheEntry entry{.info = GeolocationInfo{},
                   .expiry_time =
                       std::chrono::steady_clock::now() + config_.negative_ttl,
                   .is_valid = false};

  cache_[ip] = std::move(entry);
  update_memory_usage();
}

void GeolocationCache::cache_bulk(
    const std::vector<std::pair<uint32_t, GeolocationInfo>> &entries) {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  auto expiry_time = std::chrono::steady_clock::now() + config_.default_ttl;

  for (const auto &[ip, info] : entries) {
    CacheEntry entry{
        .info = info, .expiry_time = expiry_time, .is_valid = true};

    entry.info.compact();
    cache_[ip] = std::move(entry);
  }

  stats_.bulk_operations.fetch_add(1, std::memory_order_relaxed);

  // Check if we need to evict entries
  if (cache_.size() > config_.max_entries) {
    evict_lru_entries(cache_.size() - config_.max_entries);
  }

  update_memory_usage();
}

std::vector<std::optional<GeolocationCache::GeolocationInfo>>
GeolocationCache::lookup_bulk(const std::vector<uint32_t> &ips) {
  std::shared_lock<std::shared_mutex> lock(cache_mutex_);

  std::vector<std::optional<GeolocationInfo>> results;
  results.reserve(ips.size());

  auto now = std::chrono::steady_clock::now();

  for (uint32_t ip : ips) {
    auto it = cache_.find(ip);

    if (it != cache_.end() && it->second.expiry_time > now &&
        it->second.is_valid) {
      results.push_back(it->second.info);
      stats_.hits.fetch_add(1, std::memory_order_relaxed);
    } else {
      results.push_back(std::nullopt);
      stats_.misses.fetch_add(1, std::memory_order_relaxed);
    }
  }

  stats_.bulk_operations.fetch_add(1, std::memory_order_relaxed);
  return results;
}

void GeolocationCache::clear() {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  cache_.clear();
  current_memory_usage_ = 0;

  LOG(LogLevel::DEBUG, LogComponent::IO_THREATINTEL,
      "GeolocationCache cleared");
}

void GeolocationCache::cleanup_expired() {
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);

  auto now = std::chrono::steady_clock::now();
  size_t removed = 0;

  for (auto it = cache_.begin(); it != cache_.end();) {
    if (it->second.expiry_time <= now) {
      it = cache_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  if (removed > 0) {
    stats_.expired_entries.fetch_add(removed, std::memory_order_relaxed);
    update_memory_usage();

    LOG(LogLevel::DEBUG, LogComponent::IO_THREATINTEL,
        "Cleaned up " << removed << " expired geolocation entries");
  }
}

size_t GeolocationCache::get_entry_count() const {
  std::shared_lock<std::shared_mutex> lock(cache_mutex_);
  return cache_.size();
}

size_t GeolocationCache::get_memory_usage() const {
  return current_memory_usage_.load();
}

size_t GeolocationCache::compact() {
  size_t initial_memory = get_memory_usage();
  cleanup_expired();

  // Additional compaction: shrink strings
  std::unique_lock<std::shared_mutex> lock(cache_mutex_);
  for (auto &[ip, entry] : cache_) {
    entry.info.compact();
  }

  update_memory_usage();
  size_t final_memory = get_memory_usage();

  return initial_memory - final_memory;
}

void GeolocationCache::on_memory_pressure(size_t pressure_level) {
  if (pressure_level > 70) {
    size_t target_reduction = get_entry_count() / 4; // Remove 25%
    evict_lru_entries(target_reduction);

    LOG(LogLevel::WARN, LogComponent::IO_THREATINTEL,
        "GeolocationCache evicted entries due to memory pressure: "
            << pressure_level);
  }
}

void GeolocationCache::evict_lru_entries(size_t target_count) {
  // Simple eviction strategy - remove entries closest to expiry
  std::vector<std::pair<uint32_t, std::chrono::steady_clock::time_point>>
      candidates;

  for (const auto &[ip, entry] : cache_) {
    candidates.emplace_back(ip, entry.expiry_time);
  }

  // Sort by expiry time (earliest first)
  std::sort(candidates.begin(), candidates.end(),
            [](const auto &a, const auto &b) { return a.second < b.second; });

  size_t to_remove = std::min(target_count, candidates.size());
  for (size_t i = 0; i < to_remove; ++i) {
    cache_.erase(candidates[i].first);
  }

  if (to_remove > 0) {
    stats_.evicted_entries.fetch_add(to_remove, std::memory_order_relaxed);
    update_memory_usage();
  }
}

void GeolocationCache::update_memory_usage() {
  size_t total = 0;

  for (const auto &[ip, entry] : cache_) {
    total += sizeof(uint32_t) + sizeof(CacheEntry);
    total += calculate_entry_size(entry.info);
  }

  current_memory_usage_ = total;
}

std::chrono::seconds
GeolocationCache::get_ttl(std::chrono::seconds requested_ttl) const {
  return requested_ttl.count() > 0 ? requested_ttl : config_.default_ttl;
}

size_t
GeolocationCache::calculate_entry_size(const GeolocationInfo &info) const {
  return info.country_code.size() + info.country_name.size() +
         info.city.size() + info.isp.size() + sizeof(double) * 2 + // lat/lon
         sizeof(uint32_t);                                         // asn
}
