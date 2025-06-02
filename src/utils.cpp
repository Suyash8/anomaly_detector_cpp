#include "utils.hpp"
#include <chrono>
#include <sstream>

namespace Utils {
std::vector<std::string> split_string(const std::string &text, char delimiter) {
  std::vector<std::string> tokens;
  std::string current_token;
  std::istringstream token_stream(text);

  while (std::getline(token_stream, current_token, delimiter)) {
    tokens.push_back(current_token);
  }
  return tokens;
}

uint64_t convert_log_time_to_ms(const std::string &log_time_str) {
  // TODO: This will be tackled later
  // for now, return a dummy value
  if (log_time_str.empty()) {
    // return get_current_time_ms(); // Not correct for actual log time
  }

  return 123456789000;
}

uint64_t get_current_time_ms() {
  auto now = std::chrono::system_clock::now();
  auto epoch = now.time_since_epoch();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
  return ms.count();
}
} // namespace Utils