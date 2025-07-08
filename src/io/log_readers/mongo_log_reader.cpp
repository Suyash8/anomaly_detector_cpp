#include "mongo_log_reader.hpp"
#include "core/config.hpp"
#include "core/log_entry.hpp"
#include "io/db/mongo_manager.hpp"
#include "utils/utils.hpp"

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/document/view.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/types-fwd.hpp>
#include <bsoncxx/types.hpp>
#include <cstdint>
#include <mongocxx/cursor-fwd.hpp>
#include <mongocxx/exception/query_exception.hpp>

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

// --- Helper Functions specific to this reader ---

static void parse_request_details(const std::string &full_request_field,
                                  std::string &out_method,
                                  std::string &out_path,
                                  std::string &out_protocol) {
  if (full_request_field.empty() || full_request_field == "-") {
    out_method = "-";
    out_path = "-";
    out_protocol = "-";
    return;
  }

  size_t method_end = full_request_field.find(' ');
  if (method_end == std::string::npos) {
    out_method = "-";
    out_path = full_request_field;
    out_protocol = "-";
    return;
  }
  out_method = full_request_field.substr(0, method_end);

  size_t protocol_start = full_request_field.rfind(' ');
  if (protocol_start == std::string::npos || protocol_start <= method_end) {
    out_path = full_request_field.substr(method_end + 1);
    out_protocol = "-";
    return;
  }
  out_protocol = full_request_field.substr(protocol_start + 1);
  out_path = full_request_field.substr(method_end + 1,
                                       protocol_start - (method_end + 1));

  if (out_path.empty())
    out_path = "/";
}

std::string get_string_or_default(const bsoncxx::document::view &doc,
                                  const std::string &key,
                                  const std::string &default_value) {
  auto element = doc[key];
  if (element && element.type() == bsoncxx::type::k_string)
    return std::string(element.get_string().value);
  return default_value;
}

// --- MongoLogReader Implementation ---

MongoLogReader::MongoLogReader(std::shared_ptr<MongoManager> manager,
                               const Config::MongoLogSourceConfig &config,
                               const std::string &reader_state_path)
    : mongo_manager_(manager), config_(config),
      reader_state_path_(reader_state_path) {
  load_state();
  std::cout
      << "MongoLogReader initialized. Will start reading logs after timestamp: "
      << last_processed_timestamp_ms_ << std::endl;
}

MongoLogReader::~MongoLogReader() { save_state(); }

void MongoLogReader::load_state() {
  std::ifstream state_file(reader_state_path_);
  if (state_file.is_open())
    state_file >> last_processed_timestamp_ms_;
  else {
    std::cout
        << "No reader state file found. Will process logs from the beginning."
        << std::endl;
    last_processed_timestamp_ms_ = 0;
  }
}

void MongoLogReader::save_state() const {
  std::ofstream state_file(reader_state_path_);
  if (state_file.is_open())
    state_file << last_processed_timestamp_ms_;
  else
    std::cerr << "Error: Could not save reader state to " << reader_state_path_
              << std::endl;
}

LogEntry MongoLogReader::bson_to_log_entry(const bsoncxx::document::view &doc) {
  LogEntry entry;
  entry.successfully_parsed_structure = true;
  entry.original_line_number = 0;
  entry.raw_log_line = bsoncxx::to_json(doc);

  // --- Direct Mappings ---
  entry.ip_address = get_string_or_default(doc, "host", "-");    // 0
  entry.remote_user = get_string_or_default(doc, "user", "-");   // 1
  entry.timestamp_str = get_string_or_default(doc, "time", "-"); // 2
  entry.http_status_code =
      Utils::string_to_number<int>(get_string_or_default(doc, "st", "0")); // 6
  entry.bytes_sent = Utils::string_to_number<uint64_t>(
      get_string_or_default(doc, "bytes", "0"));           // 7
  entry.referer = get_string_or_default(doc, "pr", "-");   // 8
  entry.user_agent = get_string_or_default(doc, "c", "-"); // 9
  entry.host = get_string_or_default(doc, "domain",
                                     "-");                           // 10
  entry.country_code = get_string_or_default(doc, "country", "-");   // 11
  entry.upstream_addr = get_string_or_default(doc, "upstream", "-"); // 12

  // --- Parsed Timings ---
  entry.request_time_s = Utils::string_to_number<double>(
      get_string_or_default(doc, "req", "0.0")); // 3
  entry.upstream_response_time_s = Utils::string_to_number<double>(
      get_string_or_default(doc, "ups", "0.0")); // 4

  // --- Main Timestamp Field (Crucial for querying) ---
  auto ts_element = doc[config_.timestamp_field_name];
  if (ts_element && ts_element.type() == bsoncxx::type::k_date) {
    auto datetime = ts_element.get_date();
    entry.parsed_timestamp_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(datetime.value)
            .count();
  } else {
    // Fallback to parsing the string timestamp if the date object is missing.
    entry.parsed_timestamp_ms =
        Utils::convert_log_time_to_ms(entry.timestamp_str);
  }

  if (!entry.parsed_timestamp_ms) {
    entry.successfully_parsed_structure = false;
  }

  // --- Deconstructed Fields ---
  std::string full_request = get_string_or_default(doc, "url", "-");
  parse_request_details(full_request, entry.request_method, entry.request_path,
                        entry.request_protocol);
  entry.request_path = Utils::url_decode(entry.request_path);

  std::string requestid_field = get_string_or_default(doc, "requestid", "|");
  size_t delimiter_pos = requestid_field.find('|');
  if (delimiter_pos != std::string::npos) {
    entry.x_request_id = requestid_field.substr(0, delimiter_pos);
    entry.accept_encoding = requestid_field.substr(delimiter_pos + 1);
  } else {
    entry.x_request_id = requestid_field;
    entry.accept_encoding = "-";
  }

  return entry;
}

std::vector<LogEntry> MongoLogReader::get_next_batch() {
  std::vector<LogEntry> batch;
  try {
    auto client = mongo_manager_->get_client();
    auto collection = (*client)[config_.database][config_.collection];

    using bsoncxx::builder::stream::close_document;
    using bsoncxx::builder::stream::document;
    using bsoncxx::builder::stream::finalize;
    using bsoncxx::builder::stream::open_document;

    auto query_filter =
        document{} << config_.timestamp_field_name << open_document << "$gt"
                   << bsoncxx::types::b_date{std::chrono::milliseconds{
                          last_processed_timestamp_ms_}}
                   << close_document << finalize;

    mongocxx::options::find opts{};
    opts.sort(document{} << config_.timestamp_field_name << 1 << finalize);
    opts.limit(BATCH_SIZE);

    mongocxx::cursor cursor = collection.find(query_filter.view(), opts);

    uint64_t latest_ts_in_batch = last_processed_timestamp_ms_;
    for (const auto &doc : cursor) {
      LogEntry entry = bson_to_log_entry(doc);
      if (entry.parsed_timestamp_ms) {
        batch.push_back(entry);
        if (*entry.parsed_timestamp_ms > latest_ts_in_batch)
          latest_ts_in_batch = *entry.parsed_timestamp_ms;
      }
    }

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