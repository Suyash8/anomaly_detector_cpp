#ifndef BASE_LOG_READER_HPP
#define BASE_LOG_READER_HPP

#include "core/log_entry.hpp"

#include <vector>

class ILogReader {
public:
  virtual ~ILogReader() = default;

  // Fetches the next batch of log entries
  // The definition of a "batch" is implementation-specific
  // Returns an empty vector if no new logs are available
  virtual std::vector<LogEntry> get_next_batch() = 0;
};

#endif // BASE_LOG_READER_HPP
