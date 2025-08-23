// Copyright (c) 2018-2025 XCASH Project, Derived from The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "int-util.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "difficulty.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;


  uint64_t next_difficulty_64(std::vector<uint64_t> timestamps, std::vector<uint64_t> cumulative_difficulties, size_t target_seconds) {
    (void)timestamps;
    (void)cumulative_difficulties;
    (void)target_seconds;
    return 1;
  }

#if defined(_MSC_VER)
#ifdef max
#undef max
#endif
#endif

  const difficulty_type max64bit(std::numeric_limits<std::uint64_t>::max());
  const boost::multiprecision::uint256_t max128bit(std::numeric_limits<boost::multiprecision::uint128_t>::max());
  const boost::multiprecision::uint512_t max256bit(std::numeric_limits<boost::multiprecision::uint256_t>::max());

#define FORCE_FULL_128_BITS

  bool check_hash(const crypto::hash &hash, difficulty_type difficulty) {
    (void)hash;
    (void)difficulty;
    return true;  // In DPoPS, PoW is not used
  }

  difficulty_type next_difficulty(std::vector<uint64_t> timestamps, std::vector<difficulty_type> cumulative_difficulties, size_t target_seconds) {
    (void)timestamps;
    (void)cumulative_difficulties;
    (void)target_seconds;
    return 1;  // Fixed difficulty under DPoPS
  }

  std::string hex(difficulty_type v)
  {
    static const char chars[] = "0123456789abcdef";
    std::string s;
    while (v > 0)
    {
      s.push_back(chars[(v & 0xf).convert_to<unsigned>()]);
      v >>= 4;
    }
    if (s.empty())
      s += "0";
    std::reverse(s.begin(), s.end());
    return "0x" + s;
  }

}