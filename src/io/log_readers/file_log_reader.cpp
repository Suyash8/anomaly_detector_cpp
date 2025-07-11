#include "file_log_reader.hpp"
#include "core/log_entry.hpp"
#include "core/logger.hpp"
#include "utils/scoped_timer.hpp"

#include <iostream>
#include <string>
#include <vector>

FileLogReader::FileLogReader(const std::string &filepath) {
  log_file_stream_.open(filepath);
  if (!is_open()) {
    std::cerr << "Error: Could not open log file: " << filepath << std::endl;
    LOG(LogLevel::FATAL, LogComponent::IO_READER,
        "Failed to open log source file: " << filepath << ". Exiting.");
    throw std::runtime_error("Failed to open log source file: " + filepath);
  } else
    LOG(LogLevel::INFO, LogComponent::IO_READER,
        "Successfully opened log file: " << filepath);
}

FileLogReader::~FileLogReader() {
  if (log_file_stream_.is_open())
    log_file_stream_.close();
  LOG(LogLevel::INFO, LogComponent::IO_READER,
      "FileLogReader closed. Total lines read: " << line_number_);
}

bool FileLogReader::is_open() const { return log_file_stream_.is_open(); }

std::vector<LogEntry> FileLogReader::get_next_batch() {
  static Histogram *batch_fetch_timer =
      MetricsManager::instance().register_histogram(
          "ad_log_reader_batch_fetch_duration_seconds{type=\"file\"}",
          "Latency of fetching a batch from a file source.");
  ScopedTimer timer(*batch_fetch_timer);

  std::vector<LogEntry> batch;
  if (!is_open()) {
    LOG(LogLevel::ERROR, LogComponent::IO_READER,
        "Log file is not open. Cannot read next batch.");
    return batch;
  }

  batch.reserve(BATCH_SIZE);
  std::string line;

  while (batch.size() < BATCH_SIZE && std::getline(log_file_stream_, line)) {
    if (!line.empty()) {
      line_number_++;
      // This reader is responsible for the initial parsing from string
      if (auto entry_opt =
              LogEntry::parse_from_string(std::move(line), line_number_, false))
        batch.push_back(*entry_opt);
    }
  }

  LOG(LogLevel::DEBUG, LogComponent::IO_READER,
      "Read " << batch.size() << " log entries from file at line number "
              << line_number_);

  // If we are at the end of the file, clear the stream's error state
  // to allow for live monitoring (tailing the file)
  if (log_file_stream_.eof())
    log_file_stream_.clear();

  return batch;
}