#ifndef JSON_FORMATTER_HPP
#define JSON_FORMATTER_HPP

#include "core/alert.hpp"
#include "nlohmann/json.hpp"

#include <string>
#include <string_view>

namespace JsonFormatter {

nlohmann::json alert_to_json_object(const Alert &alert_data);

std::string format_alert_to_json(const Alert &alert_data);
std::string escape_json_value(std::string_view input);

} // namespace JsonFormatter

#endif // JSON_FORMATTER_HPP