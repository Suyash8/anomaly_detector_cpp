#ifndef UTILS_HPP
#define UTILS_HPP

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace Utils {
std::vector<std::string> split_string(const std::string &text, char delimiter);
std::vector<std::string_view> split_string_view(std::string_view str,
                                                char delimiter);
std::optional<uint64_t> convert_log_time_to_ms(std::string_view log_time_str);
uint64_t get_current_time_ms();
std::string url_decode(std::string_view encoded_string);

void save_string(std::ofstream &out, std::string_view s);
std::string load_string(std::ifstream &in);

struct CIDRBlock {
  uint32_t network_address = 0;
  uint32_t netmask = 0;

  bool contains(uint32_t ip) const;
};

std::optional<CIDRBlock> parse_cidr(std::string_view cidr_string);
uint32_t ip_string_to_uint32(std::string_view ip_str);

template <typename T> std::optional<T> string_to_number(std::string_view s) {
  if (s.empty() || s == "-") {
    if constexpr (std::is_floating_point_v<T>)
      return static_cast<T>(0.0);
    if constexpr (std::is_integral_v<T>)
      return static_cast<T>(0);
    return std::nullopt;
  }

  T value;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);

  if (ec == std::errc() && ptr == s.data() + s.size())
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

inline std::string trim_copy(std::string_view sv) {
  std::string s{sv};
  trim_inplace(s);
  return s;
}
} // namespace Utils

#endif // UTILS_HPP