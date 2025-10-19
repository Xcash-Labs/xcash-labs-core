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

#pragma once

#define TX_EXTRA_PADDING_MAX_COUNT          255
#define TX_EXTRA_NONCE_MAX_COUNT            255

#define TX_EXTRA_TAG_PADDING                0x00
#define TX_EXTRA_TAG_PUBKEY                 0x01
#define TX_EXTRA_NONCE                      0x02
#define TX_EXTRA_MERGE_MINING_TAG           0x03
#define TX_EXTRA_TAG_ADDITIONAL_PUBKEYS     0x04
#define TX_EXTRA_VRF_SIGNATURE_TAG          0x07

#define TX_EXTRA_NONCE_PAYMENT_ID           0x00
#define TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID 0x01
#define TX_EXTRA_TAG_PUBLIC_TX_V1           0xFA

namespace cryptonote
{

  // ===== X-Cash Public TX (v1) – header-only helpers =====
  struct tx_extra_public_tx_v1 {
    uint8_t version = 1;
    std::string recipient_addr_str;  // ≤255B
    std::string sender_addr_str;     // ≤255B
    uint64_t output_index = 0;       // varint on wire
    uint64_t amount_atomic = 0;      // u64 LE
    crypto::signature sig{};         // 64B
  };

  static inline void xcash_write_varint(std::string& out, uint64_t v) {
    // Correct 7-bit groups with continuation bit
    while (v >= 0x80) {
      out.push_back(static_cast<uint8_t>((v & 0x7F) | 0x80));
      v >>= 7;
    }
    out.push_back(static_cast<uint8_t>(v));
  }

  template <typename T>
  static inline void xcash_write_le(std::string& out, T v) {
    for (size_t i = 0; i < sizeof(T); ++i)
      out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
  }

  // Serialize payload (includes version; signature written LAST)
  static inline bool xcash_serialize_public_tx_v1(const tx_extra_public_tx_v1& x,
                                                  std::string& data) {
    // Per-field cap so a single length byte is enough for each string
    if (x.recipient_addr_str.size() > 255) return false;
    if (x.sender_addr_str.size()    > 255) return false;

    data.clear();
    data.reserve(1 + 1 + x.recipient_addr_str.size() + 1 + x.sender_addr_str.size()
                + 10 /*varint idx*/ + 8 /*amount*/ + 64 /*sig*/);

    // version
    data.push_back(x.version);

    // recipient (len + bytes)
    data.push_back(static_cast<uint8_t>(x.recipient_addr_str.size()));
    data.append(x.recipient_addr_str.data(), x.recipient_addr_str.size());

    // sender (len + bytes)
    data.push_back(static_cast<uint8_t>(x.sender_addr_str.size()));
    data.append(x.sender_addr_str.data(), x.sender_addr_str.size());

    // output_index (varint) + amount (u64 LE)
    xcash_write_varint(data, x.output_index);
    xcash_write_le<uint64_t>(data, x.amount_atomic);

    // signature (64 bytes) — write LAST to match signing/verification message layout
    data.append(reinterpret_cast<const char*>(&x.sig), sizeof(x.sig));

    return true;
  }

  // Append Tag | VarintLen | Data into tx.extra
  static inline bool xcash_add_public_tx_v1(std::vector<uint8_t>& extra,
                                            const tx_extra_public_tx_v1& x) {
    std::string payload;
    if (!xcash_serialize_public_tx_v1(x, payload))
      return false;

    // Tag
    extra.push_back(TX_EXTRA_TAG_PUBLIC_TX_V1); // e.g. 0xFA

    // Varint length (do NOT cap to 255—addresses + sig can exceed that)
    std::string lenbuf;
    xcash_write_varint(lenbuf, static_cast<uint64_t>(payload.size()));
    extra.insert(extra.end(), lenbuf.begin(), lenbuf.end());

    // Data
    extra.insert(extra.end(), payload.begin(), payload.end());
    return true;
  }
  // end

  struct tx_extra_padding
  {
    size_t size;

    // load
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<false>& ar)
    {
      // size - 1 - because of variant tag
      for (size = 1; size <= TX_EXTRA_PADDING_MAX_COUNT; ++size)
      {
        if (ar.eof())
          break;

        uint8_t zero;
        if (!::do_serialize(ar, zero))
          return false;

        if (0 != zero)
          return false;
      }

      return size <= TX_EXTRA_PADDING_MAX_COUNT;
    }

    // store
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<true>& ar)
    {
      if(TX_EXTRA_PADDING_MAX_COUNT < size)
        return false;

      // i = 1 - because of variant tag
      for (size_t i = 1; i < size; ++i)
      {
        uint8_t zero = 0;
        if (!::do_serialize(ar, zero))
          return false;
      }
      return true;
    }
  };

  struct tx_extra_pub_key
  {
    crypto::public_key pub_key;

    BEGIN_SERIALIZE()
      FIELD(pub_key)
    END_SERIALIZE()
  };

  struct tx_extra_nonce
  {
    std::string nonce;
    BEGIN_SERIALIZE()
      FIELD(nonce)
      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size()) return false;
    END_SERIALIZE()
  };

  struct tx_extra_merge_mining_tag
  {
    struct serialize_helper
    {
      tx_extra_merge_mining_tag& mm_tag;

      serialize_helper(tx_extra_merge_mining_tag& mm_tag_) : mm_tag(mm_tag_)
      {
      }

      BEGIN_SERIALIZE()
        VARINT_FIELD_N("depth", mm_tag.depth)
        FIELD_N("merkle_root", mm_tag.merkle_root)
      END_SERIALIZE()
    };

    uint64_t depth;
    crypto::hash merkle_root;

    // load
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<false>& ar)
    {
      std::string field;
      if(!::do_serialize(ar, field))
        return false;

      binary_archive<false> iar{epee::strspan<std::uint8_t>(field)};
      serialize_helper helper(*this);
      return ::serialization::serialize(iar, helper);
    }

    // store
    template <template <bool> class Archive>
    bool member_do_serialize(Archive<true>& ar)
    {
      std::ostringstream oss;
      binary_archive<true> oar(oss);
      serialize_helper helper(*this);
      if(!::do_serialize(oar, helper))
        return false;

      std::string field = oss.str();
      return ::serialization::serialize(ar, field);
    }
  };

  // per-output additional tx pubkey for multi-destination transfers involving at least one subaddress
  struct tx_extra_additional_pub_keys
  {
    std::vector<crypto::public_key> data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_vrf_signature
  {
    std::vector<uint8_t> data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  typedef boost::variant<tx_extra_padding, tx_extra_pub_key, tx_extra_nonce, tx_extra_merge_mining_tag, tx_extra_additional_pub_keys, tx_extra_vrf_signature> tx_extra_field;
}

VARIANT_TAG(binary_archive, cryptonote::tx_extra_padding, TX_EXTRA_TAG_PADDING);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_pub_key, TX_EXTRA_TAG_PUBKEY);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_nonce, TX_EXTRA_NONCE);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_merge_mining_tag, TX_EXTRA_MERGE_MINING_TAG);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_additional_pub_keys, TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
VARIANT_TAG(binary_archive, cryptonote::tx_extra_vrf_signature, TX_EXTRA_VRF_SIGNATURE_TAG);