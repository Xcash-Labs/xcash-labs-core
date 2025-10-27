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

#include <sstream>
#include <numeric>
#include <boost/algorithm/string.hpp>
#include "misc_language.h"
#include "syncobj.h"
#include "cryptonote_basic_impl.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "file_io_utils.h"
#include "common/command_line.h"
#include "common/util.h"
#include "string_coding.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h"
#include "time_helper.h"
#include "boost/logic/tribool.hpp"
#include <boost/filesystem.hpp>

#ifdef __APPLE__
  #include <sys/times.h>
  #include <IOKit/IOKitLib.h>
  #include <IOKit/ps/IOPSKeys.h>
  #include <IOKit/ps/IOPowerSources.h>
  #include <mach/mach_host.h>
  #include <AvailabilityMacros.h>
  #include <TargetConditionals.h>
#elif defined(__linux__)
  #include <unistd.h>
  #include <sys/resource.h>
  #include <sys/times.h>
  #include <time.h>
#elif defined(__FreeBSD__)
  #include <devstat.h>
  #include <errno.h>
  #include <fcntl.h>
#if defined(__amd64__) || defined(__i386__) || defined(__x86_64__)
  #include <machine/apm_bios.h>
#endif
  #include <stdio.h>
  #include <sys/resource.h>
  #include <sys/sysctl.h>
  #include <sys/times.h>
  #include <sys/types.h>
  #include <unistd.h>
#endif

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "miner"

#define AUTODETECT_WINDOW 10 // seconds
#define AUTODETECT_GAIN_THRESHOLD 1.02f  // 2%

using namespace epee;

#include "miner.h"
#include "crypto/hash.h"


extern "C" void slow_hash_allocate_state();
extern "C" void slow_hash_free_state();
namespace cryptonote
{

  namespace
  {
    const command_line::arg_descriptor<std::string> arg_extra_messages =  {"extra-messages-file", "Specify file for extra messages to include into coinbase transactions", "", true};
    const command_line::arg_descriptor<std::string> arg_start_mining =    {"start-mining", "Specify wallet address to mining for", "", true};
    const command_line::arg_descriptor<uint32_t>      arg_mining_threads =  {"mining-threads", "Specify mining threads count", 0, true};
    const command_line::arg_descriptor<bool>        arg_bg_mining_enable =  {"bg-mining-enable", "enable background mining", true, true};
    const command_line::arg_descriptor<bool>        arg_bg_mining_ignore_battery =  {"bg-mining-ignore-battery", "if true, assumes plugged in when unable to query system power status", false, true};    
    const command_line::arg_descriptor<uint64_t>    arg_bg_mining_min_idle_interval_seconds =  {"bg-mining-min-idle-interval", "Specify min lookback interval in seconds for determining idle state", miner::BACKGROUND_MINING_DEFAULT_MIN_IDLE_INTERVAL_IN_SECONDS, true};
    const command_line::arg_descriptor<uint16_t>     arg_bg_mining_idle_threshold_percentage =  {"bg-mining-idle-threshold", "Specify minimum avg idle percentage over lookback interval", miner::BACKGROUND_MINING_DEFAULT_IDLE_THRESHOLD_PERCENTAGE, true};
    const command_line::arg_descriptor<uint16_t>     arg_bg_mining_miner_target_percentage =  {"bg-mining-miner-target", "Specify maximum percentage cpu use by miner(s)", miner::BACKGROUND_MINING_DEFAULT_MINING_TARGET_PERCENTAGE, true};
  }

  void miner::resume()
  {

  }

  bool miner::stop()
  {
    return true;
  }
//-----------------------------------------------------------------------------------------------------
  bool miner::is_mining() const
  {
    return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const block& bl, const difficulty_type& di, uint64_t height, uint64_t block_reward)
  {
    CRITICAL_REGION_LOCAL(m_template_lock);
    m_template = bl;
    m_diffic = di;
    m_height = height;
    m_block_reward = block_reward;
    ++m_template_no;
    m_starter_nonce = crypto::rand<uint32_t>();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update()
  {
    if(!is_mining())
      return true;

    return request_block_template();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template()
  {
    block bl;
    difficulty_type di = AUTO_VAL_INIT(di);
    uint64_t height = AUTO_VAL_INIT(height);
    uint64_t expected_reward; //only used for RPC calls - could possibly be useful here too?

    cryptonote::blobdata extra_nonce;
    if(m_extra_messages.size() && m_config.current_extra_message_index < m_extra_messages.size())
    {
      extra_nonce = m_extra_messages[m_config.current_extra_message_index];
    }

    uint64_t cumulative_weight;
    uint64_t seed_height;
    crypto::hash seed_hash;
    if(!m_phandler->get_block_template(bl, m_mine_address, di, height, expected_reward, cumulative_weight, extra_nonce, seed_height, seed_hash))
    {
      LOG_ERROR("Failed to get_block_template(), stopping mining");
      return false;
    }
    set_block_template(bl, di, height, expected_reward);
    return true;
  }
//-----------------------------------------------------------------------------------------------------
  bool miner::find_nonce_for_given_block(const get_block_hash_t &gbh, block& bl, const difficulty_type& diffic, uint64_t height, const crypto::hash *seed_hash)
  {
    for(; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++)
    {
      crypto::hash h;
      gbh(bl, height, seed_hash, diffic <= 100 ? 0 : tools::get_max_concurrency(), h);

      if(check_hash(h, diffic))
      {
        bl.invalidate_hashes();
        return true;
      }
    }
    bl.invalidate_hashes();
    return false;
  }

}
