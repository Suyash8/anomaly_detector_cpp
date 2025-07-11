#include "aho_corasick.hpp"

#include <cstddef>
#include <queue>

namespace Utils {

AhoCorasick::AhoCorasick(const std::vector<std::string> &patterns)
    : patterns_(patterns) {
  trie_.emplace_back(); // Root node

  // 1. Build the basic trie structure
  for (size_t i = 0; i < patterns.size(); ++i) {
    int node = 0;
    for (char ch : patterns[i]) {
      if (trie_[node].children.find(ch) == trie_[node].children.end()) {
        trie_[node].children[ch] = trie_.size();
        trie_.emplace_back();
      }
      node = trie_[node].children[ch];
    }
    trie_[node].pattern_indices.push_back(i);
  }

  // 2. Build suffix and output links using BFS
  std::queue<int> q;
  for (auto const &[key, val] : trie_[0].children) {
    q.push(val);
  }

  while (!q.empty()) {
    int u = q.front();
    q.pop();

    for (auto const &[ch, v] : trie_[u].children) {
      int j = trie_[u].suffix_link;
      while (j > 0 && trie_[j].children.find(ch) == trie_[j].children.end()) {
        j = trie_[j].suffix_link;
      }
      if (trie_[j].children.count(ch)) {
        trie_[v].suffix_link = trie_[j].children[ch];
      }
      q.push(v);
    }

    // Build output links
    int suffix_node = trie_[u].suffix_link;
    if (!trie_[suffix_node].pattern_indices.empty()) {
      trie_[u].output_link = suffix_node;
    } else {
      trie_[u].output_link = trie_[suffix_node].output_link;
    }
  }
}

std::vector<std::string> AhoCorasick::find_all(std::string_view text) const {
  std::vector<std::string> found_patterns;
  int current_node = 0;

  for (char ch : text) {
    while (current_node > 0 && trie_[current_node].children.find(ch) ==
                                   trie_[current_node].children.end()) {
      current_node = trie_[current_node].suffix_link;
    }
    if (trie_[current_node].children.count(ch)) {
      current_node = trie_[current_node].children.at(ch);
    }

    int temp_node = current_node;
    while (temp_node > 0) {
      if (!trie_[temp_node].pattern_indices.empty()) {
        for (int pattern_idx : trie_[temp_node].pattern_indices) {
          found_patterns.push_back(patterns_[pattern_idx]);
        }
      }
      temp_node = trie_[temp_node].output_link;
    }
  }
  return found_patterns;
}

} // namespace Utils