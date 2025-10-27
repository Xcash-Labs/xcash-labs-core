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

namespace cryptonote
{
  miner::miner(i_miner_handler* phandler, const get_block_hash_t &gbh)
    : m_stop(true), m_phandler(phandler), m_gbh(gbh) {}

  miner::~miner() { /* no-op */ }

  // --- CLI opts: ignore all mining args so --help doesn’t show bogus options.
  void miner::init_options(boost::program_options::options_description& /*desc*/)
  {
    // Intentionally no mining options exposed, disabled.
  }

  // --- init: ignore any passed mining flags and never arm background mining.
  bool miner::init(const boost::program_options::variables_map& /*vm*/, network_type /*nettype*/)
  {
    m_is_background_mining_enabled = false;
    m_do_mining = false;
    m_threads_total = 0;
    return true;
  }

  // --- Status/getters return safe zeros/defaults ---
  bool miner::is_mining() const { return false; }
  const account_public_address& miner::get_mining_address() const { return m_mine_address; }
  uint32_t miner::get_threads_count() const { return 0; }
  uint64_t miner::get_speed() const { return 0; }
  bool miner::get_is_background_mining_enabled() const { return false; }
  bool miner::get_ignore_battery() const { return true; } // “don’t care”

  // --- No-ops / safe returns ---
  bool miner::start(const account_public_address&, size_t, bool, bool)
  {
    MINFO("Mining is disabled in this xcash fork.");
    return false;
  }
  bool miner::stop() { return true; }
  void miner::send_stop_signal() { /* no-op */ }
  bool miner::on_block_chain_update() { return true; }
  bool miner::request_block_template() { return false; }
  bool miner::on_idle() { return true; }
  void miner::do_print_hashrate(bool) { /* no-op */ }
  void miner::merge_hr() { /* no-op */ }
  void miner::update_autodetection() { /* no-op */ }

  // Background mining controls: accept but don’t enable
  bool miner::set_is_background_mining_enabled(bool) { m_is_background_mining_enabled = false; return false; }
  void miner::set_ignore_battery(bool) { /* no-op */ }
  uint64_t miner::get_min_idle_seconds() const { return 0; }
  bool miner::set_min_idle_seconds(uint64_t) { return false; }
  uint8_t miner::get_idle_threshold() const { return 100; }
  bool miner::set_idle_threshold(uint8_t) { return false; }
  uint8_t miner::get_mining_target() const { return 0; }
  bool miner::set_mining_target(uint8_t) { return false; }

  void miner::pause() { /* no-op */ }
  void miner::resume() { /* no-op */ }
  bool miner::background_worker_thread() { return true; }

  // Never try to solve a block
  bool miner::find_nonce_for_given_block(const get_block_hash_t&, block&, const difficulty_type&, uint64_t, const crypto::hash*)
  {
    return false;
  }

  // Do nothing on sync
  void miner::on_synchronized() {}

  // Platform helpers become unreachable; keep them if headers require them
  bool miner::get_system_times(uint64_t& total, uint64_t& idle) { total = idle = 0; return false; }
  bool miner::get_process_time(uint64_t& total) { total = 0; return false; }
  uint8_t miner::get_percent_of_total(uint64_t other, uint64_t total) { return total ? (uint8_t)((other*100.0)/total) : 0; }
  boost::logic::tribool miner::on_battery_power() { return boost::logic::tribool(false); }

} // namespace cryptonote