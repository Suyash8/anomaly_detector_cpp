#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace Utils {
std::vector<std::string> split_string(const std::string &text, char delimiter);
uint64_t convert_log_time_to_ms(const std::string &log_time_str);
uint64_t get_current_time_ms();
} // namespace Utils

#endif // UTILS_HPP