#include "ua_parser.hpp"
#include "utils.hpp"

#include <cstddef>
#include <exception>
#include <optional>
#include <string>

namespace UAParser {
std::optional<int> get_major_version(const std::string &ua,
                                     const std::string &browser_token) {
  size_t pos = ua.find(browser_token);
  if (pos == std::string::npos)
    return std::nullopt;

  size_t version_start = pos + browser_token.length();
  if (version_start >= ua.length())
    return std::nullopt;

  size_t version_end = ua.find_first_not_of("0123456789", version_start);
  std::string major_version_string =
      ua.substr(version_start, version_end - version_start);

  if (major_version_string.empty())
    return std::nullopt;

  try {
    return *Utils::string_to_number<int>(major_version_string);
  } catch (const std::exception &) {
    return std::nullopt;
  }
}
} // namespace UAParser