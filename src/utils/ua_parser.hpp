#ifndef UA_PARSER_HPP
#define UA_PARSER_HPP

#include <optional>
#include <string_view>

namespace UAParser {
std::optional<int> get_major_version(std::string_view ua,
                                     std::string_view browser_token);
}

#endif // UA_PARSER_HPP