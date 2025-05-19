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
#include <memory>
#include "serialization.h"
#include "serialization/binary_utils.h"
#include <iostream>

/*
template <template <bool> class Archive>
inline bool do_serialize(Archive<false>& ar, std::string& str)
{
  size_t size = 0;
  ar.serialize_varint(size);
  if (ar.remaining_bytes() < size)
  {
    ar.set_fail();
    return false;
  }

  std::unique_ptr<std::string::value_type[]> buf(new std::string::value_type[size]);
  ar.serialize_blob(buf.get(), size);
  str.erase();
  str.append(buf.get(), size);
  return true;
}


template <template <bool> class Archive>
inline bool do_serialize(Archive<true>& ar, std::string& str)
{
  size_t size = str.size();
  ar.serialize_varint(size);
  ar.serialize_blob(const_cast<std::string::value_type*>(str.c_str()), size);
  return true;
}


template <template <bool> class Archive>
inline bool do_serialize(Archive<false>& ar, std::string& str)
{
  size_t size = 0;
  ar.serialize_varint(size);
  if (ar.remaining_bytes() < size)
  {
    ar.set_fail();
    return false;
  }

  std::unique_ptr<std::string::value_type[]> buf(new std::string::value_type[size]);
  ar.serialize_blob(buf.get(), size);
  str.assign(buf.get(), size);
  return true;
}

template <template <bool> class Archive>
inline bool do_serialize(Archive<true>& ar, std::string& str)
{
  size_t size = str.size();
  ar.serialize_varint(size);
  ar.serialize_blob(const_cast<std::string::value_type*>(str.data()), size);
  return true;
}
*/

  

template <template <bool> class Archive>
inline bool do_serialize(Archive<false>& ar, std::string& str)
{
//  size_t size = 0;
  uint8_t size = 0;
  ar.serialize_varint(size);   // jed need to check
  std::cout << "[DEBUG] do_serialize (read): varint size = " << size << std::endl;

  if (ar.remaining_bytes() < size)
  {
    std::cout << "[DEBUG] do_serialize (read): insufficient remaining bytes, needed = " << size
              << ", available = " << ar.remaining_bytes() << std::endl;
    ar.set_fail();
    return false;
  }

  std::unique_ptr<std::string::value_type[]> buf(new std::string::value_type[size]);
  ar.serialize_blob(buf.get(), size);
  str.assign(buf.get(), size);

  std::cout << "[DEBUG] do_serialize (read): string content loaded, actual size = " << str.size() << std::endl;
  return true;
}

template <template <bool> class Archive>
inline bool do_serialize(Archive<true>& ar, std::string& str)
{
  size_t size = str.size();
  std::cout << "[DEBUG] do_serialize (write): writing string of size = " << size << std::endl;

  ar.serialize_varint(size);
  ar.serialize_blob(const_cast<std::string::value_type*>(str.data()), size);

  std::cout << "[DEBUG] do_serialize (write): string data written" << std::endl;
  return true;
}
