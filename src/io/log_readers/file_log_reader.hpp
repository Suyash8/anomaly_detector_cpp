#ifndef FILE_LOG_READER_HPP
#define FILE_LOG_READER_HPP

#include "base_log_reader.hpp"
#include <fstream>
#include <string>
#include <vector>

// An implementation of ILogReader that reads log entries from a text file
class FileLogReader : public ILogReader {
public:
  explicit FileLogReader(const std::string &filepath);
  ~FileLogReader() override;

  std::vector<LogEntry> get_next_batch() override;
  bool is_open() const;

private:
  std::ifstream log_file_stream_;
  uint64_t line_number_ = 0;
  static constexpr size_t BATCH_SIZE = 1000;
};

#endif // FILE_LOG_READER_HPP