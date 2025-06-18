#include "utils.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <exception>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>

namespace Utils {
std::string url_decode(const std::string &encoded_string) {
  std::ostringstream decoded_stream;

  for (size_t i = 0; i < encoded_string.length(); i++) {
    if (encoded_string[i] == '%' && i + 2 < encoded_string.length()) {
      std::string hex = encoded_string.substr(i + 1, 2);
      try {
        char decoded_char = static_cast<char>(std::stoi(hex, nullptr, 16));
        decoded_stream << decoded_char;
        i += 2;
      } catch (const std::exception &) {
        decoded_stream << '%';
      }
    } else if (encoded_string[i] == '+')
      decoded_stream << ' ';
    else
      decoded_stream << encoded_string[i];
  }
  return decoded_stream.str();
}

std::vector<std::string> split_string(const std::string &text, char delimiter) {
  std::vector<std::string> tokens;
  std::string current_token;
  std::istringstream token_stream(text);

  while (std::getline(token_stream, current_token, delimiter)) {
    tokens.push_back(current_token);
  }
  return tokens;
}

std::optional<uint64_t>
convert_log_time_to_ms(const std::string &log_time_str) {
  if (log_time_str.empty() || log_time_str == "-") {
    return std::nullopt;
  }

  std::tm t{};
  std::istringstream ss(log_time_str);

  // The format string for std::get_time
  // %d: day of the month
  // %b: abbreviated month name (locale-dependent, "May" for English)
  // %Y: year with century
  // %H:%M:%S: hour, minute, second
  ss >> std::get_time(&t, "%d/%b/%Y:%H:%M:%S");

  if (ss.fail()) {
    // std::cerr << "Time parsing failed (std::get_time) for: " << log_time_str
    //           << std::endl;
    return std::nullopt;
  }

  std::time_t epoch_seconds = mktime(&t);

  if (epoch_seconds == -1) {
    // std::cerr << "Time parsing failed (mktime) for: " << log_time_str
    //           << std::endl;
    return std::nullopt;
  }

  return static_cast<uint64_t>(epoch_seconds) * 1000;
}

uint64_t get_current_time_ms() {
  auto now = std::chrono::system_clock::now();
  auto epoch = now.time_since_epoch();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
  return ms.count();
}
} // namespace Utils