#include "mongo_log_reader.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "io/db/mongo_manager.hpp"
#include "utils/scoped_timer.hpp"

#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/document/view.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/types-fwd.hpp>
#include <bsoncxx/types.hpp>
#include <mongocxx/cursor-fwd.hpp>
#include <mongocxx/exception/query_exception.hpp>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

// --- MongoLogReader Implementation ---

MongoLogReader::MongoLogReader(std::shared_ptr<MongoManager> manager,
                               const Config::MongoLogSourceConfig &config,
                               const std::string &reader_state_path)
    : mongo_manager_(manager), config_(config),
      reader_state_path_(reader_state_path) {
  load_state();
  LOG(LogLevel::INFO, LogComponent::IO_READER,
      "MongoLogReader initialized. Will start reading logs after timestamp: "
          << last_processed_timestamp_ms_);
}

MongoLogReader::~MongoLogReader() { save_state(); }

void MongoLogReader::load_state() {
  std::ifstream state_file(reader_state_path_);
  if (state_file.is_open())
    state_file >> last_processed_timestamp_ms_;
  else {
    LOG(LogLevel::INFO, LogComponent::IO_READER,
        "No reader state file found. Will process logs from the beginning.");
    last_processed_timestamp_ms_ = 0;
  }
}

void MongoLogReader::save_state() const {
  std::ofstream state_file(reader_state_path_);
  if (state_file.is_open())
    state_file << last_processed_timestamp_ms_;
  else
    LOG(LogLevel::ERROR, LogComponent::IO_READER,
        "Error: Could not save reader state to " << reader_state_path_);
}

std::optional<LogEntry>
MongoLogReader::bson_to_log_entry(const bsoncxx::document::view &doc) {

  auto get_string = [&](const char *key) -> std::string_view {
    auto element = doc[key];
    if (element && element.type() == bsoncxx::type::k_string)
      return std::string_view(element.get_string().value);
    return "-";
  };

  std::string line = std::string(get_string("host")); // 0 ip_address
  line += '|' + std::string(get_string("user"));      // 1 remote_user
  line += '|' + std::string(get_string("time"));      // 2 timestamp_str
  line += '|' + std::string(get_string("req"));       // 3 request_time_s
  line += '|' + std::string(get_string("ups"));    // 4 upstream_response_time_s
  line += '|' + std::string(get_string("url"));    // 5 full_request
  line += '|' + std::string(get_string("st"));     // 6 status_code
  line += '|' + std::string(get_string("bytes"));  // 7 bytes_sent
  line += '|' + std::string(get_string("pr"));     // 8 referer
  line += '|' + std::string(get_string("c"));      // 9 user_agent
  line += '|' + std::string(get_string("domain")); // 10 host
  line += '|' + std::string(get_string("country"));   // 11 country_code
  line += '|' + std::string(get_string("upstream"));  // 12 upstream_addr
  line += '|' + std::string(get_string("requestid")); // 13 x_request_id

  LOG(LogLevel::TRACE, LogComponent::IO_READER,
      "Parsed log entry from BSON: " << line);

  auto entry = LogEntry::parse_from_string(std::move(line), 0, false);
  LOG(LogLevel::TRACE, LogComponent::IO_READER,
      "Converted BSON to LogEntry successfully");

  return entry;
}

std::vector<LogEntry> MongoLogReader::get_next_batch() {
  static Histogram *batch_fetch_timer =
      MetricsManager::instance().register_histogram(
          "ad_log_reader_batch_fetch_duration_seconds{type=\"mongodb\"}",
          "Latency of fetching a batch from a MongoDB source.");
  ScopedTimer timer(*batch_fetch_timer);

  std::vector<LogEntry> batch;
  try {
    auto client = mongo_manager_->get_client();
    auto collection = (*client)[config_.database][config_.collection];

    LOG(LogLevel::TRACE, LogComponent::IO_READER,
        "Initiating MongoDB query for log entries after timestamp: "
            << last_processed_timestamp_ms_);

    LOG(LogLevel::TRACE, LogComponent::IO_READER,
        "MongoDB query parameters: "
            << "Database: " << config_.database
            << ", Collection: " << config_.collection
            << ", Timestamp field: " << config_.timestamp_field_name
            << ", Last processed timestamp: " << last_processed_timestamp_ms_);

    bsoncxx::builder::basic::document filter_builder{};

    // Build the sub-document for the $gt (greater than) operator
    bsoncxx::builder::basic::document gt_builder{};
    gt_builder.append(bsoncxx::builder::basic::kvp(
        "$gt", bsoncxx::types::b_date(
                   std::chrono::milliseconds(last_processed_timestamp_ms_))));

    // Add the { timestamp_field: { $gt: ... } } sub-document to the main filter
    filter_builder.append(bsoncxx::builder::basic::kvp(
        config_.timestamp_field_name, gt_builder.view()));

    mongocxx::options::find opts{};

    // Build the sort document using the core builder
    bsoncxx::builder::basic::document sort_builder{};
    sort_builder.append(
        bsoncxx::builder::basic::kvp(config_.timestamp_field_name, 1));
    opts.sort(sort_builder.view());

    opts.limit(BATCH_SIZE);

    mongocxx::cursor cursor = collection.find(filter_builder.view(), opts);

    uint64_t latest_ts_in_batch = last_processed_timestamp_ms_;
    for (const auto &doc : cursor) {
      if (auto entry_opt = bson_to_log_entry(doc))
        if (entry_opt->parsed_timestamp_ms) {
          batch.push_back(std::move(*entry_opt));
          if (*(batch.back().parsed_timestamp_ms) > latest_ts_in_batch)
            latest_ts_in_batch = *(batch.back().parsed_timestamp_ms);
        }
    }

    LOG(LogLevel::DEBUG, LogComponent::IO_READER,
        "Fetched a batch of " << batch.size() << " log entries from MongoDB.");

    if (latest_ts_in_batch > last_processed_timestamp_ms_) {
      last_processed_timestamp_ms_ = latest_ts_in_batch;
      save_state(); // Persist the new state immediately
    }
  } catch (const mongocxx::query_exception &e) {
    std::cerr << "MongoDB query failed: " << e.what() << std::endl;
    // Back off for a bit before retrying to avoid spamming a down DB
    std::this_thread::sleep_for(std::chrono::seconds(5));
  } catch (const std::exception &e) {
    std::cerr << "An error occurred in MongoLogReader: " << e.what()
              << std::endl;
  }

  return batch;
}