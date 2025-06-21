#include "state_serializer.hpp"

#include <optional>
#include <vector>

namespace StateSerializer {

// Empty stubs to allow compilation
std::vector<char> serialize(const PerIpState &state) { return {}; }
std::vector<char> serialize(const PerPathState &state) { return {}; }
std::optional<PerIpState> deserialize_ip_state(const std::vector<char> &data) {
  return std::nullopt;
}
std::optional<PerPathState>
deserialize_path_state(const std::vector<char> &data) {
  return std::nullopt;
}

} // namespace StateSerializer