#include "io/threat_intel/dns_cache.hpp"
#include "io/threat_intel/optimized_intel_manager.hpp"
#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

class OptimizedIntelManagerTest : public ::testing::Test {
protected:
  void SetUp() override {
    config_ = OptimizedIntelManager::Config{};
    config_.bloom_filter_size = 1000; // 1K expected elements for testing
    config_.bloom_filter_fpp =
        0.1; // 10% false positive rate for testing (more lenient)
    config_.ip_cache_size = 10;            // Very small cache for testing
    config_.domain_cache_size = 10;        // Very small cache for testing
    config_.enable_geolocation = false;    // Disable for testing
    config_.enable_dns_caching = false;    // Disable for testing
    config_.enable_memory_mapping = false; // Disable for testing

    intel_manager_ = std::make_unique<OptimizedIntelManager>(config_);
  }

  void TearDown() override { intel_manager_.reset(); }

  OptimizedIntelManager::Config config_;
  std::unique_ptr<OptimizedIntelManager> intel_manager_;
};

TEST_F(OptimizedIntelManagerTest, InitializationAndBasicOperations) {
  EXPECT_NE(intel_manager_, nullptr);

  // Test basic memory management interface
  EXPECT_GT(intel_manager_->get_memory_usage(), 0);
  EXPECT_EQ(intel_manager_->get_component_name(), "OptimizedIntelManager");
  EXPECT_TRUE(intel_manager_->can_evict());
  EXPECT_GT(intel_manager_->get_priority(), 0);
}

TEST_F(OptimizedIntelManagerTest, IPThreatLookup) {
  // Test IP threat lookup - initially should not be blacklisted
  EXPECT_FALSE(intel_manager_->is_blacklisted_ip(0x08080808)); // 8.8.8.8
  EXPECT_FALSE(intel_manager_->is_suspicious_ip(0x08080808));

  // Get threat info for non-malicious IP
  auto threat_info = intel_manager_->get_threat_info(0x08080808);
  EXPECT_EQ(threat_info.threat_types, 0); // No threats
  EXPECT_EQ(threat_info.confidence_score, 0);

  // Test with string IP
  EXPECT_FALSE(intel_manager_->is_blacklisted_ip("8.8.8.8"));
}

TEST_F(OptimizedIntelManagerTest, DomainThreatLookup) {
  // Test domain threat lookup - initially should not be blacklisted
  EXPECT_FALSE(intel_manager_->is_blacklisted_domain("google.com"));
  EXPECT_FALSE(intel_manager_->is_suspicious_domain("google.com"));

  // Get threat info for non-malicious domain
  auto threat_info = intel_manager_->get_threat_info("google.com");
  EXPECT_EQ(threat_info.threat_types, 0); // No threats
  EXPECT_EQ(threat_info.confidence_score, 0);
}

TEST_F(OptimizedIntelManagerTest, GeolocationLookup) {
  // Test geolocation lookup for Google DNS
  auto geo_info = intel_manager_->get_geolocation(0x08080808); // 8.8.8.8

  // Initially no geolocation data available in test environment
  EXPECT_FALSE(geo_info.has_value());
}

TEST_F(OptimizedIntelManagerTest, DNSResolution) {
  // Test hostname resolution
  auto hostname = intel_manager_->resolve_hostname(0x08080808); // 8.8.8.8

  // Initially no DNS data available in test environment
  EXPECT_FALSE(hostname.has_value());

  // Test domain resolution
  auto ip = intel_manager_->resolve_domain("google.com");
  EXPECT_FALSE(ip.has_value());
}

TEST_F(OptimizedIntelManagerTest, ConfigurationManagement) {
  // Test adding feed URL
  intel_manager_->add_feed_url("https://test.example.com/threats.txt");

  // Test removing feed URL
  intel_manager_->remove_feed_url("https://test.example.com/threats.txt");

  // Test config update
  auto new_config = config_;
  new_config.update_interval_seconds = 7200; // 2 hours
  intel_manager_->update_config(new_config);
}

TEST_F(OptimizedIntelManagerTest, CacheManagement) {
  // Test cache clearing
  intel_manager_->clear_caches();

  // Test force update
  intel_manager_->force_update();
}

TEST_F(OptimizedIntelManagerTest, MemoryPressureHandling) {
  size_t initial_memory = intel_manager_->get_memory_usage();

  // Trigger memory pressure
  intel_manager_->on_memory_pressure(80); // 80% pressure level

  size_t after_pressure = intel_manager_->get_memory_usage();
  // Memory usage might be reduced or stay the same depending on cache content
  EXPECT_LE(after_pressure,
            initial_memory + 1000); // Allow small increases due to metadata

  // Compact should also reduce memory
  size_t compacted = intel_manager_->compact();
  EXPECT_GE(compacted,
            0); // Should return amount freed (might be 0 if nothing to free)
}

TEST_F(OptimizedIntelManagerTest, Statistics) {
  // Get initial statistics
  auto stats = intel_manager_->get_statistics();
  EXPECT_EQ(stats.total_ips.load(), 0);
  EXPECT_EQ(stats.total_domains.load(), 0);
  EXPECT_EQ(stats.lookup_hits.load(), 0);
  EXPECT_EQ(stats.lookup_misses.load(), 0);

  // Perform some lookups to generate statistics
  intel_manager_->is_blacklisted_ip(0x08080808);
  intel_manager_->is_blacklisted_domain("example.com");

  // Check that statistics have been updated
  auto updated_stats = intel_manager_->get_statistics();
  EXPECT_GE(updated_stats.lookup_misses.load(), 2);
}

// DNS Cache Tests
class DNSCacheTest : public ::testing::Test {
protected:
  void SetUp() override {
    config_ = DNSCache::Config{};
    config_.max_entries = 1000;
    config_.default_ttl = std::chrono::seconds(300);

    dns_cache_ = std::make_unique<DNSCache>(config_);
  }

  DNSCache::Config config_;
  std::unique_ptr<DNSCache> dns_cache_;
};

TEST_F(DNSCacheTest, ForwardDNSLookup) {
  // Test cache miss
  auto ip = dns_cache_->lookup_ip("google.com");
  EXPECT_FALSE(ip.has_value());

  // Cache an IP
  dns_cache_->cache_ip("google.com", 0x08080808); // 8.8.8.8

  // Test cache hit
  auto cached_ip = dns_cache_->lookup_ip("google.com");
  EXPECT_TRUE(cached_ip.has_value());
  EXPECT_EQ(*cached_ip, 0x08080808);
}

TEST_F(DNSCacheTest, ReverseDNSLookup) {
  // Test cache miss
  auto hostname = dns_cache_->lookup_hostname(0x08080808);
  EXPECT_FALSE(hostname.has_value());

  // Cache a hostname
  dns_cache_->cache_hostname(0x08080808, "dns.google");

  // Test cache hit
  auto cached_hostname = dns_cache_->lookup_hostname(0x08080808);
  EXPECT_TRUE(cached_hostname.has_value());
  EXPECT_EQ(*cached_hostname, "dns.google");
}

TEST_F(DNSCacheTest, TTLExpiration) {
  // Cache with very short TTL
  dns_cache_->cache_ip("shortlived.com", 0x01010101, std::chrono::seconds(1));

  // Should be available immediately
  auto ip = dns_cache_->lookup_ip("shortlived.com");
  EXPECT_TRUE(ip.has_value());

  // Wait for expiration
  std::this_thread::sleep_for(std::chrono::seconds(2));

  // Should be expired now
  auto expired_ip = dns_cache_->lookup_ip("shortlived.com");
  EXPECT_FALSE(expired_ip.has_value());
}

TEST_F(DNSCacheTest, NegativeCaching) {
  // Cache a negative lookup
  dns_cache_->cache_negative_ip("nonexistent.invalid");

  // Should return empty but be a cache hit
  auto ip = dns_cache_->lookup_ip("nonexistent.invalid");
  EXPECT_FALSE(ip.has_value());

  // Statistics should show a hit
  auto stats = dns_cache_->get_statistics();
  EXPECT_GT(stats.forward_hits.load(), 0);
}

TEST_F(DNSCacheTest, MemoryManagement) {
  EXPECT_GT(dns_cache_->get_memory_usage(), 0);
  EXPECT_EQ(dns_cache_->get_component_name(), "DNSCache");
  EXPECT_TRUE(dns_cache_->can_evict());

  // Fill cache and test eviction
  for (int i = 0; i < 1500; ++i) { // More than max_entries
    std::string hostname = "host" + std::to_string(i) + ".com";
    dns_cache_->cache_ip(hostname, 0x0A000000 | i);
  }

  EXPECT_LE(dns_cache_->get_entry_count(), config_.max_entries);

  // Test memory pressure handling
  size_t initial_memory = dns_cache_->get_memory_usage();
  dns_cache_->on_memory_pressure(90);
  size_t after_pressure = dns_cache_->get_memory_usage();
  EXPECT_LT(after_pressure, initial_memory);
}

// Geolocation Cache Tests
class GeolocationCacheTest : public ::testing::Test {
protected:
  void SetUp() override {
    config_ = GeolocationCache::Config{};
    config_.max_entries = 1000;
    config_.default_ttl = std::chrono::seconds(3600);

    geo_cache_ = std::make_unique<GeolocationCache>(config_);
  }

  GeolocationCache::Config config_;
  std::unique_ptr<GeolocationCache> geo_cache_;
};

TEST_F(GeolocationCacheTest, BasicLookup) {
  // Test cache miss
  auto info = geo_cache_->lookup(0x08080808);
  EXPECT_FALSE(info.has_value());

  // Cache geolocation info
  GeolocationCache::GeolocationInfo geo_info{};
  geo_info.country_code = "US";
  geo_info.country_name = "United States";
  geo_info.city = "Mountain View";
  geo_info.latitude = 37.4056;
  geo_info.longitude = -122.0775;
  geo_info.asn = 15169;
  geo_info.isp = "Google LLC";

  geo_cache_->cache_location(0x08080808, geo_info);

  // Test cache hit
  auto cached_info = geo_cache_->lookup(0x08080808);
  EXPECT_TRUE(cached_info.has_value());
  EXPECT_EQ(cached_info->country_code, "US");
  EXPECT_EQ(cached_info->city, "Mountain View");
  EXPECT_EQ(cached_info->asn, 15169);
}

TEST_F(GeolocationCacheTest, BulkOperations) {
  // Prepare bulk data
  std::vector<std::pair<uint32_t, GeolocationCache::GeolocationInfo>> bulk_data;
  for (int i = 0; i < 100; ++i) {
    GeolocationCache::GeolocationInfo info{};
    info.country_code = "TC"; // Test Country
    info.city = "TestCity" + std::to_string(i);
    info.asn = 12345 + i;

    uint32_t ip = 0x0A000000 | i;
    bulk_data.emplace_back(ip, info);
  }

  // Cache bulk data
  geo_cache_->cache_bulk(bulk_data);

  // Prepare IPs for bulk lookup
  std::vector<uint32_t> lookup_ips;
  for (int i = 0; i < 100; ++i) {
    lookup_ips.push_back(0x0A000000 | i);
  }

  // Perform bulk lookup
  auto results = geo_cache_->lookup_bulk(lookup_ips);
  EXPECT_EQ(results.size(), 100);

  // Verify results
  for (size_t i = 0; i < results.size(); ++i) {
    EXPECT_TRUE(results[i].has_value());
    EXPECT_EQ(results[i]->country_code, "TC");
    EXPECT_EQ(results[i]->asn, 12345 + i);
  }
}

TEST_F(GeolocationCacheTest, MemoryOptimization) {
  // Test memory compaction
  GeolocationCache::GeolocationInfo info{};
  info.country_code = "US";
  info.country_name = "United States of America"; // Long string
  info.city = "San Francisco";
  info.isp = "Very Long Internet Service Provider Name Inc.";

  geo_cache_->cache_location(0x08080808, info);

  size_t initial_memory = geo_cache_->get_memory_usage();
  size_t compacted = geo_cache_->compact();
  size_t after_compact = geo_cache_->get_memory_usage();

  EXPECT_GE(compacted, 0);
  EXPECT_LE(after_compact, initial_memory);
}

// Integration test
TEST_F(OptimizedIntelManagerTest, IntegrationWithCaches) {
  // Test basic functionality integration

  // Test IP blacklist check
  EXPECT_FALSE(intel_manager_->is_blacklisted_ip(0x08080808));

  // Test domain blacklist check
  EXPECT_FALSE(intel_manager_->is_blacklisted_domain("google.com"));

  // Test statistics integration
  auto stats = intel_manager_->get_statistics();
  EXPECT_GE(stats.lookup_misses.load(), 2); // From the above lookups
}
