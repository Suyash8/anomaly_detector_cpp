#include "utils.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

std::vector<std::string_view> split_string_view(std::string_view str,
                                                char delimiter) {
  std::vector<std::string_view> result;
  size_t start = 0;
  size_t end = str.find(delimiter);
  while (end != std::string_view::npos) {
    result.push_back(str.substr(start, end - start));
    start = end + 1;
    end = str.find(delimiter, start);
  }
  result.push_back(str.substr(start));
  return result;
}

std::optional<uint64_t>
convert_log_time_to_ms(const std::string &log_time_str) {
  if (log_time_str.empty() || log_time_str == "-") {
    return std::nullopt;
  }

  // Expected format: 23/May/2025:00:00:35 +0530
  std::tm t{};
  const char *p = log_time_str.c_str();

  // Day
  char *end;
  t.tm_mday = strtol(p, &end, 10);
  if (end == p || *end != '/')
    return std::nullopt;
  p = end + 1;

  // Month
  static const std::unordered_map<std::string, int> month_map = {
      {"Jan", 0}, {"Feb", 1}, {"Mar", 2}, {"Apr", 3}, {"May", 4},  {"Jun", 5},
      {"Jul", 6}, {"Aug", 7}, {"Sep", 8}, {"Oct", 9}, {"Nov", 10}, {"Dec", 11}};
  char month_str[4] = {0};
  if (sscanf(p, "%3s", month_str) != 1)
    return std::nullopt;

  auto it = month_map.find(month_str);
  if (it == month_map.end())
    return std::nullopt;

  t.tm_mon = it->second;
  p += 3;
  if (*p != '/')
    return std::nullopt;
  p++;

  // Year, hour, minute, second
  if (sscanf(p, "%d:%d:%d:%d", &t.tm_year, &t.tm_hour, &t.tm_min, &t.tm_sec) !=
      4)
    return std::nullopt;
  t.tm_year -= 1900;

  // Advance p to the space before the timezone
  while (*p && *p != ' ')
    p++;
  if (*p != ' ')
    return std::nullopt;
  p++;

  // Timezone
  int tz_hour = 0, tz_min = 0;
  char tz_sign;
  if (sscanf(p, "%c%02d%02d", &tz_sign, &tz_hour, &tz_min) != 3) {
    return std::nullopt;
  }

  // Use timegm/mkgmtime for a direct UTC conversion from struct tm
  // This avoids locale/timezone issues with mktime
#if defined(_WIN32)
  std::time_t epoch_seconds = _mkgmtime(&t);
#else
  std::time_t epoch_seconds = timegm(&t);
#endif

  if (epoch_seconds == -1) {
    return std::nullopt;
  }

  // The timegm function treats the tm struct as if it were in UTC
  // The original timestamp was at a specific offset, so we must adjust
  // our UTC time to match what the original time represented
  int tz_offset_seconds = (tz_hour * 3600) + (tz_min * 60);
  if (tz_sign == '-') {
    epoch_seconds += tz_offset_seconds;
  } else { // '+'
    epoch_seconds -= tz_offset_seconds;
  }

  return static_cast<uint64_t>(epoch_seconds) * 1000;
}

uint64_t get_current_time_ms() {
  auto now = std::chrono::system_clock::now();
  auto epoch = now.time_since_epoch();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
  return ms.count();
}

uint32_t ip_string_to_uint32(const std::string &ip_str) {
  uint32_t ip_uint = 0;
  std::istringstream ip_stream(ip_str);
  std::string segment;
  int i = 3;
  while (std::getline(ip_stream, segment, '.')) {
    if (i < 0)
      return 0;

    try {
      ip_uint |= (std::stoi(segment) & 0xFF) << (i * 8);
    } catch (...) {
      return 0;
    }
    i--;
  }
  return (i == -1) ? ip_uint : 0;
}

std::optional<CIDRBlock> parse_cidr(const std::string &cidr_string) {
  size_t slash_pos = cidr_string.find('/');
  if (slash_pos == std::string::npos) {
    uint32_t ip = ip_string_to_uint32(cidr_string);
    if (ip == 0)
      return std::nullopt;
    return CIDRBlock{ip, 0xFFFFFFFF};
  }

  std::string ip_part = cidr_string.substr(0, slash_pos);
  std::string mask_part = cidr_string.substr(slash_pos + 1);

  uint32_t ip = ip_string_to_uint32(ip_part);
  if (ip == 0)
    return std::nullopt;

  int mask_len = 0;
  try {
    mask_len = std::stoi(mask_part);
  } catch (...) {
    return std::nullopt;
  }

  if (mask_len < 0 || mask_len > 32)
    return std::nullopt;

  uint32_t netmask = (mask_len == 0) ? 0 : (0xFFFFFFFF << (32 - mask_len));

  return CIDRBlock{ip & netmask, netmask};
}

bool CIDRBlock::contains(uint32_t ip) const {
  return (ip & netmask) == network_address;
}
} // namespace Utils