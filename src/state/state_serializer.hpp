#ifndef STATE_SERIALIZER_HPP
#define STATE_SERIALIZER_HPP

#include "../analysis_engine.hpp"

#include <optional>
#include <vector>

namespace StateSerializer {

class Accessor;

std::vector<char> serialize(const PerIpState &state);
std::vector<char> serialize(const PerPathState &state);

std::optional<PerIpState> deserialize_ip_state(const std::vector<char> &data);
std::optional<PerPathState>
deserialize_path_state(const std::vector<char> &data);

} // namespace StateSerializer

#endif // STATE_SERIALIZER_HPP