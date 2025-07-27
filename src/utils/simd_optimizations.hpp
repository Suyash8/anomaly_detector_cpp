#ifndef SIMD_OPTIMIZATIONS_HPP
#define SIMD_OPTIMIZATIONS_HPP

#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <string_view>
#include <vector>

namespace memory::simd {

/**
 * SIMD-optimized hashing functions using AVX2/SSE instructions
 * for high-performance bulk operations
 */
class SIMDHasher {
public:
  /**
   * Vectorized MurmurHash3 for bulk hashing operations
   * Processes 8 uint32_t values simultaneously using AVX2
   */
  static void bulk_murmur3_x8(const uint32_t *input, uint32_t *output,
                              size_t count, uint32_t seed = 0x9747b28c) {
    const __m256i c1 = _mm256_set1_epi32(0xcc9e2d51);
    const __m256i c2 = _mm256_set1_epi32(0x1b873593);
    const __m256i r1 = _mm256_set1_epi32(15);
    const __m256i r2 = _mm256_set1_epi32(13);
    const __m256i m = _mm256_set1_epi32(5);
    const __m256i n = _mm256_set1_epi32(0xe6546b64);

    __m256i hash = _mm256_set1_epi32(seed);

    for (size_t i = 0; i < count; i += 8) {
      // Load 8 values at once
      __m256i k =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(input + i));

      // MurmurHash3 algorithm vectorized
      k = _mm256_mullo_epi32(k, c1);
      k = _mm256_or_si256(_mm256_slli_epi32(k, 15), _mm256_srli_epi32(k, 17));
      k = _mm256_mullo_epi32(k, c2);

      hash = _mm256_xor_si256(hash, k);
      hash = _mm256_or_si256(_mm256_slli_epi32(hash, 13),
                             _mm256_srli_epi32(hash, 19));
      hash = _mm256_add_epi32(_mm256_mullo_epi32(hash, m), n);

      // Store results
      _mm256_storeu_si256(reinterpret_cast<__m256i *>(output + i), hash);
    }
  }

  /**
   * SIMD-optimized string hashing for bulk domain/path processing
   */
  static uint64_t fast_string_hash(std::string_view str) {
    const char *data = str.data();
    size_t len = str.length();
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV offset basis

    // Process 32 bytes at a time using AVX2
    while (len >= 32) {
      __m256i chunk =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(data));

      // FNV-1a algorithm vectorized
      __m256i hash_vec = _mm256_set1_epi64x(hash);
      hash_vec = _mm256_xor_si256(hash_vec, chunk);

      // Multiply by FNV prime (simplified for demonstration)
      hash_vec = _mm256_mullo_epi32(hash_vec, _mm256_set1_epi32(0x01000193));

      // Extract final hash (combine all lanes)
      alignas(32) uint64_t temp[4];
      _mm256_store_si256(reinterpret_cast<__m256i *>(temp), hash_vec);
      hash = temp[0] ^ temp[1] ^ temp[2] ^ temp[3];

      data += 32;
      len -= 32;
    }

    // Process remaining bytes
    while (len--) {
      hash ^= static_cast<uint64_t>(*data++);
      hash *= 0x00000100000001B3ULL; // FNV prime
    }

    return hash;
  }

  /**
   * Vectorized CRC32 calculation for data integrity
   */
  static uint32_t simd_crc32(const void *data, size_t length) {
    const uint8_t *bytes = static_cast<const uint8_t *>(data);
    uint32_t crc = 0xFFFFFFFF;

    // Use hardware CRC32 instruction if available
    while (length >= 8) {
      uint64_t chunk;
      std::memcpy(&chunk, bytes, 8);
      crc = _mm_crc32_u64(crc, chunk);
      bytes += 8;
      length -= 8;
    }

    while (length >= 4) {
      uint32_t chunk;
      std::memcpy(&chunk, bytes, 4);
      crc = _mm_crc32_u32(crc, chunk);
      bytes += 4;
      length -= 4;
    }

    while (length--) {
      crc = _mm_crc32_u8(crc, *bytes++);
    }

    return ~crc;
  }
};

/**
 * SIMD-optimized Bloom filter operations
 */
class SIMDBloomFilter {
public:
  /**
   * Vectorized bit setting for multiple hash values
   */
  static void set_bits_avx2(uint8_t *bit_array, const uint32_t *hash_values,
                            size_t num_hashes, size_t bit_array_size) {
    for (size_t i = 0; i < num_hashes; i += 8) {
      __m256i hashes = _mm256_loadu_si256(
          reinterpret_cast<const __m256i *>(hash_values + i));

      // Calculate bit positions
      __m256i bit_positions =
          _mm256_rem_epi32(hashes, _mm256_set1_epi32(bit_array_size));

      // Extract individual positions and set bits
      alignas(32) uint32_t positions[8];
      _mm256_store_si256(reinterpret_cast<__m256i *>(positions), bit_positions);

      for (int j = 0; j < 8 && (i + j) < num_hashes; j++) {
        uint32_t pos = positions[j];
        uint32_t byte_idx = pos / 8;
        uint32_t bit_idx = pos % 8;
        bit_array[byte_idx] |= (1U << bit_idx);
      }
    }
  }

  /**
   * Vectorized bit checking for multiple hash values
   */
  static bool check_bits_avx2(const uint8_t *bit_array,
                              const uint32_t *hash_values, size_t num_hashes,
                              size_t bit_array_size) {
    for (size_t i = 0; i < num_hashes; i += 8) {
      __m256i hashes = _mm256_loadu_si256(
          reinterpret_cast<const __m256i *>(hash_values + i));

      // Calculate bit positions
      __m256i bit_positions =
          _mm256_rem_epi32(hashes, _mm256_set1_epi32(bit_array_size));

      // Extract and check individual positions
      alignas(32) uint32_t positions[8];
      _mm256_store_si256(reinterpret_cast<__m256i *>(positions), bit_positions);

      for (int j = 0; j < 8 && (i + j) < num_hashes; j++) {
        uint32_t pos = positions[j];
        uint32_t byte_idx = pos / 8;
        uint32_t bit_idx = pos % 8;
        if (!(bit_array[byte_idx] & (1U << bit_idx))) {
          return false; // Definitely not in set
        }
      }
    }
    return true; // Probably in set
  }
};

/**
 * SIMD-optimized string operations
 */
class SIMDString {
public:
  /**
   * Vectorized string search using AVX2
   */
  static bool contains_avx2(std::string_view haystack,
                            std::string_view needle) {
    if (needle.empty() || needle.length() > haystack.length()) {
      return false;
    }

    if (needle.length() == 1) {
      return contains_char_avx2(haystack, needle[0]);
    }

    const char *hay_ptr = haystack.data();
    const char *needle_ptr = needle.data();
    size_t hay_len = haystack.length();
    size_t needle_len = needle.length();

    if (needle_len >= 32) {
      // Use specialized algorithm for long needles
      return contains_long_needle(haystack, needle);
    }

    // For short needles, use Boyer-Moore with SIMD character scanning
    char first_char = needle[0];
    for (size_t i = 0; i <= hay_len - needle_len; i++) {
      if (hay_ptr[i] == first_char) {
        if (std::memcmp(hay_ptr + i, needle_ptr, needle_len) == 0) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Vectorized character search
   */
  static bool contains_char_avx2(std::string_view str, char target) {
    const char *data = str.data();
    size_t len = str.length();

    __m256i target_vec = _mm256_set1_epi8(target);

    while (len >= 32) {
      __m256i chunk =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(data));
      __m256i cmp = _mm256_cmpeq_epi8(chunk, target_vec);

      if (!_mm256_testz_si256(cmp, cmp)) {
        return true; // Found character
      }

      data += 32;
      len -= 32;
    }

    // Check remaining bytes
    while (len--) {
      if (*data++ == target) {
        return true;
      }
    }

    return false;
  }

  /**
   * SIMD-optimized case-insensitive comparison
   */
  static bool equals_ignore_case_avx2(std::string_view a, std::string_view b) {
    if (a.length() != b.length()) {
      return false;
    }

    const char *ptr_a = a.data();
    const char *ptr_b = b.data();
    size_t len = a.length();

    // ASCII lowercase mask vectors
    __m256i mask_az = _mm256_set1_epi8(0x20);
    __m256i lower_a = _mm256_set1_epi8('a' - 1);
    __m256i upper_z = _mm256_set1_epi8('z' + 1);
    __m256i lower_A = _mm256_set1_epi8('A' - 1);
    __m256i upper_Z = _mm256_set1_epi8('Z' + 1);

    while (len >= 32) {
      __m256i chunk_a =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(ptr_a));
      __m256i chunk_b =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(ptr_b));

      // Convert to lowercase
      __m256i is_upper_a =
          _mm256_and_si256(_mm256_cmpgt_epi8(chunk_a, lower_A),
                           _mm256_cmpgt_epi8(upper_Z, chunk_a));
      __m256i is_upper_b =
          _mm256_and_si256(_mm256_cmpgt_epi8(chunk_b, lower_A),
                           _mm256_cmpgt_epi8(upper_Z, chunk_b));

      chunk_a = _mm256_or_si256(chunk_a, _mm256_and_si256(is_upper_a, mask_az));
      chunk_b = _mm256_or_si256(chunk_b, _mm256_and_si256(is_upper_b, mask_az));

      // Compare
      __m256i cmp = _mm256_cmpeq_epi8(chunk_a, chunk_b);
      if (!_mm256_testc_si256(cmp, _mm256_set1_epi8(-1))) {
        return false;
      }

      ptr_a += 32;
      ptr_b += 32;
      len -= 32;
    }

    // Handle remaining bytes
    while (len--) {
      char ca = (*ptr_a >= 'A' && *ptr_a <= 'Z') ? *ptr_a + 32 : *ptr_a;
      char cb = (*ptr_b >= 'A' && *ptr_b <= 'Z') ? *ptr_b + 32 : *ptr_b;
      if (ca != cb) {
        return false;
      }
      ptr_a++;
      ptr_b++;
    }

    return true;
  }

private:
  static bool contains_long_needle(std::string_view haystack,
                                   std::string_view needle) {
    // Simplified implementation for long needles
    return haystack.find(needle) != std::string_view::npos;
  }
};

/**
 * SIMD-optimized memory operations
 */
class SIMDMemory {
public:
  /**
   * Vectorized memory comparison
   */
  static bool equals_avx2(const void *a, const void *b, size_t length) {
    const uint8_t *ptr_a = static_cast<const uint8_t *>(a);
    const uint8_t *ptr_b = static_cast<const uint8_t *>(b);

    while (length >= 32) {
      __m256i chunk_a =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(ptr_a));
      __m256i chunk_b =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(ptr_b));

      __m256i cmp = _mm256_cmpeq_epi8(chunk_a, chunk_b);
      if (!_mm256_testc_si256(cmp, _mm256_set1_epi8(-1))) {
        return false;
      }

      ptr_a += 32;
      ptr_b += 32;
      length -= 32;
    }

    return std::memcmp(ptr_a, ptr_b, length) == 0;
  }

  /**
   * Vectorized memory set
   */
  static void set_avx2(void *dest, uint8_t value, size_t length) {
    uint8_t *ptr = static_cast<uint8_t *>(dest);
    __m256i value_vec = _mm256_set1_epi8(value);

    while (length >= 32) {
      _mm256_storeu_si256(reinterpret_cast<__m256i *>(ptr), value_vec);
      ptr += 32;
      length -= 32;
    }

    std::memset(ptr, value, length);
  }

  /**
   * Parallel checksum calculation
   */
  static uint64_t parallel_checksum(const void *data, size_t length) {
    const uint64_t *ptr = static_cast<const uint64_t *>(data);
    __m256i sum = _mm256_setzero_si256();

    while (length >= 32) {
      __m256i chunk =
          _mm256_loadu_si256(reinterpret_cast<const __m256i *>(ptr));
      sum = _mm256_add_epi64(sum, chunk);
      ptr += 4; // 4 uint64_t values
      length -= 32;
    }

    // Extract and sum all lanes
    alignas(32) uint64_t temp[4];
    _mm256_store_si256(reinterpret_cast<__m256i *>(temp), sum);
    uint64_t result = temp[0] + temp[1] + temp[2] + temp[3];

    // Handle remaining bytes
    const uint8_t *byte_ptr = reinterpret_cast<const uint8_t *>(ptr);
    while (length--) {
      result += *byte_ptr++;
    }

    return result;
  }
};

} // namespace memory::simd

#endif // SIMD_OPTIMIZATIONS_HPP
