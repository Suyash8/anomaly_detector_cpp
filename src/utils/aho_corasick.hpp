#ifndef AHO_CORASICK_HPP
#define AHO_CORASICK_HPP

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Utils {

class AhoCorasick {
public:
  AhoCorasick(const std::vector<std::string> &patterns);
  std::vector<std::string> find_all(std::string_view text) const;

private:
  struct TrieNode {
    std::unordered_map<char, int> children;
    int suffix_link = 0; // Default to root
    int output_link = 0; // Default to root
    std::vector<int> pattern_indices;
  };

  std::vector<TrieNode> trie_;
  std::vector<std::string> patterns_;
};

} // namespace Utils

#endif // AHO_CORASICK_HPP