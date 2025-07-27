#ifndef FAST_STRING_FORMATTING_HPP
#define FAST_STRING_FORMATTING_HPP

#include <array>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace fast_string {

/**
 * @brief Fast string formatting utilities to replace sprintf/stringstream
 *
 * Optimized string operations that avoid heap allocation and provide
 * better performance than standard library alternatives.
 */

// Stack-allocated string builder for small strings
template <size_t Capacity = 256> class StackStringBuilder {
public:
  StackStringBuilder() : size_(0) { buffer_[0] = '\0'; }

  // Append string_view
  StackStringBuilder &operator<<(std::string_view str) {
    append(str);
    return *this;
  }

  // Append C string
  StackStringBuilder &operator<<(const char *str) {
    append(std::string_view(str));
    return *this;
  }

  // Append character
  StackStringBuilder &operator<<(char c) {
    if (size_ < Capacity - 1) {
      buffer_[size_++] = c;
      buffer_[size_] = '\0';
    }
    return *this;
  }

  // Append integers (fast, no allocation)
  StackStringBuilder &operator<<(int value) {
    append_integer(value);
    return *this;
  }

  StackStringBuilder &operator<<(unsigned int value) {
    append_integer(value);
    return *this;
  }

  StackStringBuilder &operator<<(long value) {
    append_integer(value);
    return *this;
  }

  StackStringBuilder &operator<<(unsigned long value) {
    append_integer(value);
    return *this;
  }

  StackStringBuilder &operator<<(long long value) {
    append_integer(value);
    return *this;
  }

  StackStringBuilder &operator<<(unsigned long long value) {
    append_integer(value);
    return *this;
  }

  // Append floating point (with precision control)
  StackStringBuilder &append_double(double value, int precision = 2) {
    if (size_ >= Capacity - 20)
      return *this; // Guard against overflow

    int written = std::snprintf(buffer_ + size_, Capacity - size_, "%.*f",
                                precision, value);
    if (written > 0 && static_cast<size_t>(written) < Capacity - size_) {
      size_ += written;
    }
    return *this;
  }

  // Fast hexadecimal formatting
  StackStringBuilder &append_hex(unsigned long long value,
                                 bool uppercase = false) {
    if (size_ >= Capacity - 20)
      return *this;

    const char *hex_chars = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";

    // Handle zero case
    if (value == 0) {
      append('0');
      return *this;
    }

    // Build hex string in reverse
    char temp[20];
    int temp_size = 0;

    while (value > 0 && temp_size < 19) {
      temp[temp_size++] = hex_chars[value & 0xF];
      value >>= 4;
    }

    // Copy reversed string to buffer
    for (int i = temp_size - 1; i >= 0 && size_ < Capacity - 1; --i) {
      buffer_[size_++] = temp[i];
    }
    buffer_[size_] = '\0';

    return *this;
  }

  // Get result
  std::string_view view() const {
    return std::string_view(buffer_.data(), size_);
  }

  std::string str() const { return std::string(buffer_.data(), size_); }

  const char *c_str() const { return buffer_.data(); }

  size_t size() const { return size_; }
  size_t capacity() const { return Capacity; }
  bool empty() const { return size_ == 0; }

  void clear() {
    size_ = 0;
    buffer_[0] = '\0';
  }

  // Reserve space (no-op for stack buffer, but provides interface
  // compatibility)
  void reserve(size_t) {}

private:
  std::array<char, Capacity + 1> buffer_; // +1 for null terminator
  size_t size_;

  void append(std::string_view str) {
    size_t to_copy = std::min(str.size(), Capacity - size_);
    if (to_copy > 0) {
      std::memcpy(buffer_.data() + size_, str.data(), to_copy);
      size_ += to_copy;
      buffer_[size_] = '\0';
    }
  }

  template <typename T> void append_integer(T value) {
    if (size_ >= Capacity - 25)
      return; // Guard against overflow

    auto result =
        std::to_chars(buffer_.data() + size_, buffer_.data() + Capacity, value);
    if (result.ec == std::errc{}) {
      size_ = result.ptr - buffer_.data();
      buffer_[size_] = '\0';
    }
  }
};

// Type aliases for common sizes
using SmallStringBuilder = StackStringBuilder<64>;
using MediumStringBuilder = StackStringBuilder<256>;
using LargeStringBuilder = StackStringBuilder<1024>;

/**
 * @brief Fast string operations
 */
namespace ops {

// Fast integer to string conversion (stack allocated)
template <typename T>
std::string_view int_to_string_view(T value, char *buffer, size_t buffer_size) {
  auto result = std::to_chars(buffer, buffer + buffer_size, value);
  if (result.ec == std::errc{}) {
    return std::string_view(buffer, result.ptr - buffer);
  }
  return "";
}

// Fast string contains check (optimized for small needles)
inline bool fast_contains(std::string_view haystack, std::string_view needle) {
  if (needle.empty())
    return true;
  if (needle.size() > haystack.size())
    return false;

  // Use Boyer-Moore-like optimization for single character
  if (needle.size() == 1) {
    char target = needle[0];
    for (char c : haystack) {
      if (c == target)
        return true;
    }
    return false;
  }

  // For small needles, use standard find
  return haystack.find(needle) != std::string_view::npos;
}

// Fast case-insensitive comparison
inline bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size())
    return false;

  for (size_t i = 0; i < a.size(); ++i) {
    char ca = a[i];
    char cb = b[i];

    // Convert to lowercase
    if (ca >= 'A' && ca <= 'Z')
      ca += 32;
    if (cb >= 'A' && cb <= 'Z')
      cb += 32;

    if (ca != cb)
      return false;
  }
  return true;
}

// Fast string starts_with (for C++17 compatibility)
inline bool starts_with(std::string_view str, std::string_view prefix) {
  return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}

// Fast string ends_with (for C++17 compatibility)
inline bool ends_with(std::string_view str, std::string_view suffix) {
  return str.size() >= suffix.size() &&
         str.substr(str.size() - suffix.size()) == suffix;
}

// Fast URL path extraction (without allocation)
inline std::string_view extract_path_from_url(std::string_view url) {
  // Find start of path (after host)
  size_t path_start = 0;

  if (starts_with(url, "http://")) {
    path_start = url.find('/', 7); // Skip "http://"
  } else if (starts_with(url, "https://")) {
    path_start = url.find('/', 8); // Skip "https://"
  } else {
    // Assume it's already a path
    path_start = 0;
  }

  if (path_start == std::string_view::npos) {
    return "/"; // Default to root
  }

  // Find end of path (before query string or fragment)
  size_t path_end = url.find_first_of("?#", path_start);
  if (path_end == std::string_view::npos) {
    path_end = url.size();
  }

  return url.substr(path_start, path_end - path_start);
}

// Fast IP address validation (basic check without allocation)
inline bool is_valid_ipv4(std::string_view ip) {
  if (ip.empty() || ip.size() > 15)
    return false;

  int dot_count = 0;
  int num = 0;
  bool has_digit = false;

  for (char c : ip) {
    if (c == '.') {
      if (!has_digit || num > 255)
        return false;
      dot_count++;
      num = 0;
      has_digit = false;
    } else if (c >= '0' && c <= '9') {
      num = num * 10 + (c - '0');
      has_digit = true;
      if (num > 255)
        return false;
    } else {
      return false; // Invalid character
    }
  }

  return dot_count == 3 && has_digit && num <= 255;
}

} // namespace ops

/**
 * @brief Compile-time string literals for static strings
 */
namespace literals {

// Common HTTP status codes
constexpr std::string_view HTTP_200 = "200";
constexpr std::string_view HTTP_404 = "404";
constexpr std::string_view HTTP_500 = "500";

// Common HTTP methods
constexpr std::string_view GET = "GET";
constexpr std::string_view POST = "POST";
constexpr std::string_view PUT = "PUT";
constexpr std::string_view DELETE = "DELETE";

// Common paths
constexpr std::string_view ROOT_PATH = "/";
constexpr std::string_view FAVICON_PATH = "/favicon.ico";
constexpr std::string_view ROBOTS_PATH = "/robots.txt";

// Common user agent patterns
constexpr std::string_view CHROME_UA = "Chrome";
constexpr std::string_view FIREFOX_UA = "Firefox";
constexpr std::string_view SAFARI_UA = "Safari";

} // namespace literals

} // namespace fast_string

#endif // FAST_STRING_FORMATTING_HPP
