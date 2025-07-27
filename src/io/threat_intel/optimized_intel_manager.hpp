#ifndef OPTIMIZED_INTEL_MANAGER_HPP
#define OPTIMIZED_INTEL_MANAGER_HPP

#include "core/memory_manager.hpp"
#include "utils/bloom_filter.hpp"
#include "utils/memory_profiler.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Forward declarations
class CompressedTrie;
class IncrementalThreatDatabase;
class DNSCache;
class GeolocationCache;

/**
 * Memory-optimized threat intelligence manager with advanced data structures
 * and efficient storage/lookup mechanisms.
 */
class OptimizedIntelManager : public memory::IMemoryManaged {
public:
  struct Config {
    std::vector<std::string> feed_urls;
    uint32_t update_interval_seconds = 3600; // 1 hour default
    size_t bloom_filter_size = 10000000;     // 10M bits (~1.25MB)
    double bloom_filter_fpp = 0.001;         // 0.1% false positive rate
    size_t ip_cache_size = 100000;           // Cache for 100K IPs
    size_t domain_cache_size = 50000;        // Cache for 50K domains
    bool enable_geolocation = true;
    bool enable_dns_caching = true;
    bool enable_memory_mapping = true;
    std::string persistence_file = "threat_intel.mdb";
  };

  struct ThreatInfo {
    enum class Type : uint8_t {
      MALICIOUS_IP = 1,
      MALICIOUS_DOMAIN = 2,
      SUSPICIOUS_IP = 4,
      SUSPICIOUS_DOMAIN = 8,
      TOR_EXIT_NODE = 16,
      VPN_ENDPOINT = 32,
      BOTNET_C2 = 64,
      PHISHING = 128
    };

    uint8_t threat_types = 0;         // Bit field of Type values
    uint32_t confidence_score = 0;    // 0-100
    uint32_t last_seen_timestamp = 0; // Unix timestamp
    uint16_t source_id = 0;           // ID of threat feed source
  };

  struct Statistics {
    std::atomic<uint64_t> total_ips{0};
    std::atomic<uint64_t> total_domains{0};
    std::atomic<uint64_t> lookup_hits{0};
    std::atomic<uint64_t> lookup_misses{0};
    std::atomic<uint64_t> bloom_filter_hits{0};
    std::atomic<uint64_t> bloom_filter_false_positives{0};
    std::atomic<uint64_t> memory_bytes_used{0};
    std::atomic<uint64_t> cache_evictions{0};
    std::atomic<uint64_t> dns_cache_hits{0};
    std::atomic<uint64_t> geolocation_cache_hits{0};

    // Copy constructor for atomic types
    Statistics() = default;
    Statistics(const Statistics &other)
        : total_ips(other.total_ips.load()),
          total_domains(other.total_domains.load()),
          lookup_hits(other.lookup_hits.load()),
          lookup_misses(other.lookup_misses.load()),
          bloom_filter_hits(other.bloom_filter_hits.load()),
          bloom_filter_false_positives(
              other.bloom_filter_false_positives.load()),
          memory_bytes_used(other.memory_bytes_used.load()),
          cache_evictions(other.cache_evictions.load()),
          dns_cache_hits(other.dns_cache_hits.load()),
          geolocation_cache_hits(other.geolocation_cache_hits.load()) {}
  };

  explicit OptimizedIntelManager(const Config &config);
  OptimizedIntelManager() : OptimizedIntelManager(Config{}) {}
  ~OptimizedIntelManager();

  // Primary threat lookup methods
  bool is_blacklisted_ip(uint32_t ip) const;
  bool is_blacklisted_ip(std::string_view ip_str) const;
  bool is_blacklisted_domain(std::string_view domain) const;
  bool is_suspicious_ip(uint32_t ip) const;
  bool is_suspicious_domain(std::string_view domain) const;

  // Enhanced threat information
  ThreatInfo get_threat_info(uint32_t ip) const;
  ThreatInfo get_threat_info(std::string_view domain) const;

  // Geolocation and DNS services
  struct GeolocationInfo {
    std::string country_code;
    std::string country_name;
    std::string city;
    double latitude = 0.0;
    double longitude = 0.0;
    uint32_t asn = 0;
    std::string isp;
  };

  std::optional<GeolocationInfo> get_geolocation(uint32_t ip) const;
  std::optional<std::string> resolve_hostname(uint32_t ip) const;
  std::optional<uint32_t> resolve_domain(std::string_view domain) const;

  // Management operations
  void force_update();
  void clear_caches();
  Statistics get_statistics() const;

  // Configuration updates
  void update_config(const Config &new_config);
  void add_feed_url(const std::string &url);
  void remove_feed_url(const std::string &url);

  // Memory management interface
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override;
  int get_priority() const override { return 50; } // Medium priority
  std::string get_component_name() const override {
    return "OptimizedIntelManager";
  }

private:
  Config config_;
  mutable Statistics stats_;

  // Core data structures
  std::unique_ptr<memory::BloomFilter<uint32_t>> ip_bloom_filter_;
  std::unique_ptr<memory::BloomFilter<uint64_t>> domain_bloom_filter_;
  std::unique_ptr<CompressedTrie> domain_trie_;
  std::unique_ptr<IncrementalThreatDatabase> threat_db_;
  std::unique_ptr<DNSCache> dns_cache_;
  std::unique_ptr<GeolocationCache> geo_cache_;
  // std::unique_ptr<MemoryMappedThreatDB> persistent_db_;  // TODO: Implement
  // later

  // Threading and synchronization
  mutable std::shared_mutex
      data_mutex_; // Reader-writer lock for data structures
  std::thread background_thread_;
  std::atomic<bool> shutdown_flag_{false};
  std::condition_variable_any cv_;
  std::mutex cv_mutex_;

  // Update tracking
  std::atomic<uint64_t> last_update_timestamp_{0};
  std::atomic<uint32_t> update_generation_{0};

  // Memory management
  size_t memory_limit_bytes_ = SIZE_MAX;
  mutable std::atomic<size_t> current_memory_usage_{0};

  // Private methods
  void background_thread_func();
  void update_feeds();
  void update_single_feed(const std::string &url, uint16_t source_id);
  void process_threat_entry(const std::string &entry, uint16_t source_id);
  void rebuild_bloom_filters();
  void handle_memory_pressure();

  // Utility methods
  uint64_t hash_domain(std::string_view domain) const;
  bool is_valid_ip_string(std::string_view ip_str) const;
  bool is_valid_domain(std::string_view domain) const;

  // Statistics helpers
  void increment_lookup_hit() const {
    stats_.lookup_hits.fetch_add(1, std::memory_order_relaxed);
  }
  void increment_lookup_miss() const {
    stats_.lookup_misses.fetch_add(1, std::memory_order_relaxed);
  }
  void increment_bloom_hit() const {
    stats_.bloom_filter_hits.fetch_add(1, std::memory_order_relaxed);
  }
  void increment_bloom_fp() const {
    stats_.bloom_filter_false_positives.fetch_add(1, std::memory_order_relaxed);
  }
};

/**
 * Compressed trie for efficient domain storage and wildcard matching
 */
class CompressedTrie : public memory::IMemoryManaged {
public:
  explicit CompressedTrie(size_t initial_capacity);
  CompressedTrie() : CompressedTrie(50000) {}
  ~CompressedTrie();

  bool insert(std::string_view domain, uint16_t source_id);
  bool contains(std::string_view domain) const;
  bool contains_subdomain(std::string_view domain) const; // Wildcard matching

  size_t size() const { return node_count_.load(); }
  void clear();

  // Memory management
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override;
  int get_priority() const override {
    return 30;
  } // Higher priority (domains are important)
  std::string get_component_name() const override { return "CompressedTrie"; }

private:
  struct TrieNode {
    std::array<std::unique_ptr<TrieNode>, 256>
        children{}; // For all ASCII chars
    bool is_terminal = false;
    uint16_t source_id = 0;
    uint32_t node_id = 0;
  };

  std::unique_ptr<TrieNode> root_;
  std::atomic<size_t> node_count_{0};
  std::atomic<size_t> memory_usage_{0};
  mutable std::shared_mutex mutex_;

  void insert_reversed(TrieNode *node, std::string_view domain,
                       uint16_t source_id);
  bool search_reversed(const TrieNode *node, std::string_view domain) const;
  void clear_node(TrieNode *node);
  size_t calculate_node_memory(const TrieNode *node) const;
};

/**
 * Incremental threat database with efficient updates and versioning
 */
class IncrementalThreatDatabase : public memory::IMemoryManaged {
public:
  explicit IncrementalThreatDatabase(size_t max_entries);
  IncrementalThreatDatabase() : IncrementalThreatDatabase(1000000) {}
  ~IncrementalThreatDatabase();

  void add_threat(uint32_t ip, const OptimizedIntelManager::ThreatInfo &info);
  void add_threat(std::string_view domain,
                  const OptimizedIntelManager::ThreatInfo &info);

  std::optional<OptimizedIntelManager::ThreatInfo>
  get_threat_info(uint32_t ip) const;
  std::optional<OptimizedIntelManager::ThreatInfo>
  get_threat_info(std::string_view domain) const;

  void begin_update(uint32_t generation);
  void commit_update();
  void rollback_update();

  size_t get_ip_count() const { return ip_threats_.size(); }
  size_t get_domain_count() const { return domain_threats_.size(); }

  // Memory management
  size_t get_memory_usage() const override;
  size_t compact() override;
  void on_memory_pressure(size_t pressure_level) override;
  bool can_evict() const override;
  int get_priority() const override {
    return 40;
  } // High priority for threat data
  std::string get_component_name() const override {
    return "IncrementalThreatDatabase";
  }

private:
  struct ThreatEntry {
    OptimizedIntelManager::ThreatInfo info;
    uint32_t generation = 0;
    bool marked_for_deletion = false;
  };

  // Use unordered_map for O(1) lookup performance
  std::unordered_map<uint32_t, ThreatEntry> ip_threats_;
  std::unordered_map<uint64_t, ThreatEntry>
      domain_threats_; // domain hash -> threat info

  mutable std::shared_mutex mutex_;
  std::atomic<uint32_t> current_generation_{0};
  std::atomic<uint32_t> update_generation_{0};
  std::atomic<bool> update_in_progress_{false};

  size_t max_entries_;
  size_t memory_limit_bytes_ = SIZE_MAX;

  void cleanup_old_entries();
  uint64_t hash_domain(std::string_view domain) const;
};

#endif // OPTIMIZED_INTEL_MANAGER_HPP
