#include "utils/string_interning.hpp"

namespace memory {

// Global string interning pool instance
static StringInternPool global_string_pool_;

StringInternPool &get_global_string_pool() { return global_string_pool_; }

} // namespace memory
