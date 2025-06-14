#ifndef UTILS_HPP
#define UTILS_HPP

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace Utils {
std::vector<std::string> split_string(const std::string &text, char delimiter);
std::optional<uint64_t> convert_log_time_to_ms(const std::string &log_time_str);
uint64_t get_current_time_ms();

template <typename T> std::optional<T> string_to_number(const std::string &s) {
  if (s.empty() || s == "-") { // Ngnix often uses "-" for empty numeric fields
    if constexpr (std::is_floating_point_v<T>)
      return static_cast<T>(0.0);
    else if constexpr (std::is_integral_v<T>)
      return static_cast<T>(0);
    return std::nullopt;
  }

  T value;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);

  if (ec == std::errc() &&
      ptr == s.data() + s.size()) // Successfully parsed the entire string
    return value;
  else if (ec == std::errc() && std::is_floating_point_v<T> &&
           ptr > s.data()) // For floating point, from_chars might successfully
                           // parse a number even if there's trailing
                           // non-numeric data
    return value;
  return std::nullopt;
}

inline void ltrim_inplace(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
          }));
}

inline void rtrim_inplace(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

inline void trim_inplace(std::string &s) {
  ltrim_inplace(s);
  rtrim_inplace(s);
}

// Non-modifying trim
inline std::string trim_copy(std::string s) {
  trim_inplace(s);
  return s;
}
} // namespace Utils

#endif // UTILS_HPP