#ifndef DNS_CACHE_HPP
#define DNS_CACHE_HPP

#include "core/memory_manager.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Forward declaration
struct ThreatInfo;

/**
 * High-performance DNS cache with TTL management and memory efficiency
 */
class DNSCache : public memory::IMemoryManaged {
public:
  struct CacheEntry {
    std::string hostname;
    std::chrono::steady_clock::time_point expiry_time;
    bool is_valid = true;
  };

  struct ReverseEntry {
    uint32_t ip;
    std::chrono::steady_clock::time_point expiry_time;
    bool is_valid = true;
  };

  struct Config {
    size_t max_entries{100000};
    std::chrono::seconds default_ttl{3600};    // 1 hour
    std::chrono::seconds negative_ttl{300};    // 5 minutes for failed lookups
    size_t max_memory_bytes{50 * 1024 * 1024}; // 50MB
  };

  explicit DNSCache(const Config &config);
  DNSCache() : DNSCache(Config{}) {}
  ~DNSCache();

  // Forward DNS lookup (hostname -> IP)
  std::optional<uint32_t> lookup_ip(std::string_view hostname);
  void cache_ip(std::string_view hostname, uint32_t ip,
                std::chrono::seconds ttl = {});
  void cache_negative_ip(std::string_view hostname); // Cache failed lookups

  // Reverse DNS lookup (IP -> hostname)
  std::optional<std::string> lookup_hostname(uint32_t ip);
  void cache_hostname(uint32_t ip, std::string_view hostname,
                      std::chrono::seconds ttl = {});
  void cache_negative_hostname(uint32_t ip); // Cache failed lookups

  // Cache management
  void clear();
  void cleanup_expired();
  size_t get_entry_count() const;

  // Statistics
  struct Statistics {
    std::atomic<uint64_t> forward_hits{0};
    std::atomic<uint64_t> forward_misses{0};
    std::atomic<uint64_t> reverse_hits{0};
    std::atomic<uint64_t> reverse_misses{0};
    std::atomic<uint64_t> expired_entries{0};
    std::atomic<uint64_t> evicted_entries{0};

    // Copy constructor for atomic types
    Statistics() = default;
    Statistics(const Statistics &other)
        : forward_hits(other.forward_hits.load()),
          forward_misses(other.forward_misses.load()),
          reverse_hits(other.reverse_hits.load()),
          reverse_misses(other.reverse_misses.load()),
          expired_entries(other.expired_entries.load()),
          evicted_entries(other.evicted_entries.load()) {}
  };

  Statistics get_statistics() const { return stats_; }

  // Memory management interface
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override { return true; }
  int get_priority() const override { return 60; } // Lower priority (cache)
  std::string get_component_name() const override { return "DNSCache"; }

private:
  Config config_;
  mutable Statistics stats_;

  // Forward cache: hostname hash -> IP
  std::unordered_map<uint64_t, ReverseEntry> forward_cache_;
  // Reverse cache: IP -> hostname
  std::unordered_map<uint32_t, CacheEntry> reverse_cache_;

  mutable std::shared_mutex cache_mutex_;
  std::atomic<size_t> current_memory_usage_{0};

  // Helper methods
  uint64_t hash_hostname(std::string_view hostname) const;
  void evict_lru_entries(size_t target_count);
  void update_memory_usage();
  std::chrono::seconds get_ttl(std::chrono::seconds requested_ttl) const;
};

/**
 * High-performance geolocation cache for IP address location data
 */
class GeolocationCache : public memory::IMemoryManaged {
public:
  struct GeolocationInfo {
    std::string country_code;
    std::string country_name;
    std::string city;
    double latitude = 0.0;
    double longitude = 0.0;
    uint32_t asn = 0;
    std::string isp;

    // Compact the strings to save memory
    void compact() {
      country_code.shrink_to_fit();
      country_name.shrink_to_fit();
      city.shrink_to_fit();
      isp.shrink_to_fit();
    }
  };

  struct CacheEntry {
    GeolocationInfo info;
    std::chrono::steady_clock::time_point expiry_time;
    bool is_valid = true;
  };

  struct Config {
    size_t max_entries{500000};                 // 500K IPs
    std::chrono::seconds default_ttl{86400};    // 24 hours
    std::chrono::seconds negative_ttl{3600};    // 1 hour for failed lookups
    size_t max_memory_bytes{100 * 1024 * 1024}; // 100MB
  };

  explicit GeolocationCache(const Config &config);
  GeolocationCache() : GeolocationCache(Config{}) {}
  ~GeolocationCache();

  // Geolocation lookup
  std::optional<GeolocationInfo> lookup(uint32_t ip);
  void cache_location(uint32_t ip, const GeolocationInfo &info,
                      std::chrono::seconds ttl = {});
  void cache_negative(uint32_t ip); // Cache failed lookups

  // Bulk operations for efficiency
  void
  cache_bulk(const std::vector<std::pair<uint32_t, GeolocationInfo>> &entries);
  std::vector<std::optional<GeolocationInfo>>
  lookup_bulk(const std::vector<uint32_t> &ips);

  // Cache management
  void clear();
  void cleanup_expired();
  size_t get_entry_count() const;

  // Statistics
  struct Statistics {
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};
    std::atomic<uint64_t> expired_entries{0};
    std::atomic<uint64_t> evicted_entries{0};
    std::atomic<uint64_t> bulk_operations{0};

    // Copy constructor for atomic types
    Statistics() = default;
    Statistics(const Statistics &other)
        : hits(other.hits.load()), misses(other.misses.load()),
          expired_entries(other.expired_entries.load()),
          evicted_entries(other.evicted_entries.load()),
          bulk_operations(other.bulk_operations.load()) {}
  };

  Statistics get_statistics() const { return stats_; }

  // Memory management interface
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override { return true; }
  int get_priority() const override {
    return 70;
  } // Lower priority (geolocation cache)
  std::string get_component_name() const override { return "GeolocationCache"; }

private:
  Config config_;
  mutable Statistics stats_;

  // Cache: IP -> GeolocationInfo
  std::unordered_map<uint32_t, CacheEntry> cache_;

  mutable std::shared_mutex cache_mutex_;
  std::atomic<size_t> current_memory_usage_{0};

  // Helper methods
  void evict_lru_entries(size_t target_count);
  void update_memory_usage();
  std::chrono::seconds get_ttl(std::chrono::seconds requested_ttl) const;
  size_t calculate_entry_size(const GeolocationInfo &info) const;
};

#endif // DNS_CACHE_HPP
