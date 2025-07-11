#include "file_log_reader.hpp"
#include "core/log_entry.hpp"

#include <iostream>
#include <string>
#include <vector>

FileLogReader::FileLogReader(const std::string &filepath) {
  log_file_stream_.open(filepath);
  if (!is_open())
    std::cerr << "Error: Could not open log file: " << filepath << std::endl;
  else
    std::cout << "Successfully opened log file: " << filepath << std::endl;
}

FileLogReader::~FileLogReader() {
  if (log_file_stream_.is_open())
    log_file_stream_.close();
}

bool FileLogReader::is_open() const { return log_file_stream_.is_open(); }

std::vector<LogEntry> FileLogReader::get_next_batch() {
  std::vector<LogEntry> batch;
  if (!is_open())
    return batch;

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

  // If we are at the end of the file, clear the stream's error state
  // to allow for live monitoring (tailing the file)
  if (log_file_stream_.eof())
    log_file_stream_.clear();

  return batch;
}