#ifndef UA_PARSER_HPP
#define UA_PARSER_HPP

#include <optional>
#include <string>

namespace UAParser {
std::optional<int> get_major_version(const std::string &ua,
                                     const std::string &browser_token);
}

#endif // UA_PARSER_HPP