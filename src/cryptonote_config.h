// Copyright (c) 2018 X-CASH Project, Derived from 2014-2018, The Monero Project
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

#include <string>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_BLOCK_SIZE                       500000000  // block header blob limit, never used!
#define CRYPTONOTE_GETBLOCKTEMPLATE_MAX_BLOCK_SIZE	196608 //size of block (bytes) that is the maximum that miners will produce
#define CRYPTONOTE_MAX_TX_SIZE                          1000000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_TRANSACTION_VERSION                     2
#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     0
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             1

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               60

// MONEY_SUPPLY - total number coins to be generated
#define MONEY_SUPPLY                                    ((uint64_t)(100000000000000000))
#define EMISSION_SPEED_FACTOR_PER_MINUTE                (19)
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)2000000000) // 2000 X-CASH per minute, creates 1051200000 X-CASH per year, which is an annual inflation of 1.05%. The start date will be around 16/06/2025

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                6
#define UPPER_TRANSACTION_SIZE                          149400 // CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE
// COIN - number of smallest units in one coin
#define COIN                                            ((uint64_t)1000000) // pow(10, 6)

#define FEE_PER_KB_OLD                                  ((uint64_t)10000) // pow(10, 4)
#define FEE_PER_KB                                      ((uint64_t)2000) // 2 * pow(10, 3)
#define FEE_PER_BYTE                                    ((uint64_t)10)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)2000) // 2 * pow(10,3)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)1000000) // 10 * pow(10,6)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)1) //((uint64_t)2000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT        ((uint64_t)3000)

#define ORPHANED_BLOCKS_MAX_COUNT                       100


#define DIFFICULTY_TARGET_V2                            60  // seconds
#define DIFFICULTY_TARGET_V1                            60  // seconds - before first fork
#define DIFFICULTY_WINDOW                               720 // blocks
#define DIFFICULTY_LAG                                  15  // !!!
#define DIFFICULTY_CUT                                  60  // timestamps to cut after sorting
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW + DIFFICULTY_LAG

// Premine the current outstand supply for swap 
#define PREMINE_BLOCK_HEIGHT								1
#define PREMINE_BLOCK_REWARD							((uint64_t)(62000000000000000))

// LWMA difficulty V8
#define HF_VERSION_LWMA_DIFFICULTY 8
#define HF_VERSION_LWMA_DIFFICULTY_BLOCK_HEIGHT 95085
#define HF_VERSION_LWMA_STARTING_DIFFICULTY 30000000
#define DIFFICULTY_TARGET_V8 60 // seconds
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V8 30 // (11)
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V8 60*4 // (60*10)
#define DIFFICULTY_WINDOW_V8 120 // (60)
#define DIFFICULTY_BLOCKS_COUNT_V8 121 //DIFFICULTY_WINDOW_V8 + 1 has to be +1 so N = N

// LWMA difficulty V9
#define DIFFICULTY_WINDOW_V9                            120
#define DIFFICULTY_BLOCKS_COUNT_V9                      121
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V9           60*4
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V9            30
#define DIFFICULTY_TARGET_V9                            60  // seconds

// LWMA difficulty V10
#define DIFFICULTY_WINDOW_V10                            120
#define DIFFICULTY_BLOCKS_COUNT_V10                      121
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V10           60*4
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V10            11
#define DIFFICULTY_TARGET_V10                            60  // seconds

// LWMA difficulty V12
#define DIFFICULTY_WINDOW_V12                            120
#define DIFFICULTY_BLOCKS_COUNT_V12                      121
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V12           60*4
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V12            11
#define DIFFICULTY_TARGET_V12                            120  // seconds

// LWMA difficulty V13
#define DIFFICULTY_WINDOW_V13                            120
#define DIFFICULTY_BLOCKS_COUNT_V13                      121
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V13           60*4
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V13            11
#define DIFFICULTY_TARGET_V13                            300  // seconds


#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V12  120 // seconds
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V13  300 // seconds
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET_V1 //just alias; used by tests


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          100  //by default, blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20     //by default, blocks count in blocks downloading

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT           1000

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                   8
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define ALLOW_DEBUG_COMMANDS

#define CRYPTONOTE_NAME                         "X-CASH"
#define CRYPTONOTE_POOLDATA_FILENAME            "X-CASH_poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "X-CASH_data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "X-CASH_lock.mdb"
#define P2P_NET_DATA_FILENAME                   "X-CASH_p2pstate.bin"
#define MINER_CONFIG_FILE_NAME                  "X-CASH_miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_DYNAMIC_FEE                  6
#define HF_VERSION_ENFORCE_RCT                  6
#define HF_VERSION_BULLETPROOFS                 10
#define HF_VERSION_MIN_MIXIN_20                 10
#define HF_VERSION_PER_BYTE_FEE                 10
#define HF_VERSION_TWO_MINUTE_BLOCK_TIME        12
#define HF_BLOCK_HEIGHT_TWO_MINUTE_BLOCK_TIME   281000

#define BLOCKCHAIN_DEFAULT_MIXIN                20

// Seed Nodes
#define SEED_NODE_1 "xcashseeds.us:18280"
#define SEED_NODE_2 "xcashseeds.uk:18280"
#define SEED_NODE_3 "xcashseeds.cc:18280"
#define SEED_NODE_4 "xcashseeds.com:18280"
#define SEED_NODE_5 "xcashseeds.net:18280"

#define SEED_NODES_LIST_1 const std::vector<std::string> m_seed_nodes_list = {SEED_NODE_1,SEED_NODE_2,SEED_NODE_3,SEED_NODE_4,SEED_NODE_5};
#define SEED_NODES_LIST_2 \
full_addrs.insert(SEED_NODE_1); \
full_addrs.insert(SEED_NODE_2); \
full_addrs.insert(SEED_NODE_3); \
full_addrs.insert(SEED_NODE_4); \
full_addrs.insert(SEED_NODE_5);

// XCASH DPOPS

// Blockchain
#define HF_VERSION_PROOF_OF_STAKE 13
#define HF_BLOCK_HEIGHT_PROOF_OF_STAKE 3 // The first block of the X-CASH proof of stake
#define BLOCK_TIME 5 // the block time in minutes
#define BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME 288 // The blocks per day with a 5 minute block time
#define MAXIMUM_RESERVE_BYTES_LEGNTH 4096 // The maximum size in bytes for the reserve bytes in the block header
#define BLOCK_TEMPLATE_BUFFER_SIZE 5000
#define XCASH_WALLET_LENGTH 98 // The length of a XCA address
#define XCASH_WALLET_PREFIX "XCA" // The prefix of a XCA address 
#define XCASH_SIGN_DATA_PREFIX "SigV1" // The prefix of a xcash_proof_of_stake_signature for the signed data
#define XCASH_SIGN_DATA_LENGTH 93 // The length of a xcash_proof_of_stake_signature for the signed data
#define BUFFER_SIZE_RESERVE_PROOF 25000 // The maximum length of a reserve proof
#define STEALTH_ADDRESS_OUTPUT_LENGTH 64 // The length of the stealth address output

// Lengths
#define BITS_IN_BYTE 8 // 8 bits in 1 byte
#define MAXIMUM_BUFFER_SIZE_DELEGATES_NAME 100 // The maximum length of the block verifiers name
#define MINIMUM_BUFFER_SIZE_DELEGATES_NAME 5 // The minimum length of the block verifiers name
#define MAXIMUM_BUFFER_SIZE_DELEGATES_BACKUP_NAMES 505 // The maximum length of the block verifiers name
#define MINIMUM_BUFFER_SIZE_DELEGATES_BACKUP_NAMES 30 // The minimum length of the block verifiers name
#define DELEGATES_PUBLIC_KEY_LENGTH 64 // The delegates public key length for signing and verifying messages

// Network
#define SEND_DATA_PORT "18283" // The port that is used by all nodes to send and receive data
#define CONNECTION_TIMEOUT_SETTINGS 1000 // the time in milliseconds for a connection to be created
#define SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS 3000 // The time in milliseconds to wait for sending or receving socket data
#define SEND_OR_RECEIVE_SOCKET_DATA_DOWNLOAD_DATABASE_HASH_TIMEOUT_SETTINGS 60000 // The time in milliseconds to wait for downloading multiple data hashes
#define SOCKET_CONNECTION_MINIMUM_BUFFER_SETTINGS 5000 // The minimum time in milliseconds, to wait before sending the data at the start time interval, since not all servers will have the same time
#define SOCKET_CONNECTION_MAXIMUM_BUFFER_SETTINGS 10000 // The maximum time in milliseconds, to wait before sending the data at the start time interval, since not all servers will have the same time
#define SOCKET_END_STRING "|END|" // End string when sending data between nodes, to signal the end of sending data

// XCASH DPOPS
#define BLOCK_VERIFIERS_TOTAL_AMOUNT 100 // The total amount of block verifiers
#define BLOCK_VERIFIERS_AMOUNT 50 // The amount of block verifiers in a round
// #define BLOCK_VERIFIERS_VALID_AMOUNT 27 // The amount of block verifiers that need to vote true for the part of the round to be valid.
// #define BLOCK_VERIFIERS_VALID_AMOUNT_PERCENTAGE 0.55 // The amount of block verifiers in a percentage that need to vote true for the part of the round to be valid.
#define BLOCK_VERIFIERS_VALID_AMOUNT 2 // The amount of block verifiers that need to vote true for the part of the round to be valid.
#define BLOCK_VERIFIERS_VALID_AMOUNT_PERCENTAGE 0.04 // The amount of block verifiers in a percentage that need to vote true for the part of the round to be valid.

// Updates data
#define BLOCK_HEIGHT_SF_V_2_2_0 2 // stealth address verification

// Network data nodes
#define NETWORK_DATA_NODES_AMOUNT 5 // The amount of network data nodes

#define NETWORK_DATA_NODE_PUBLIC_ADDRESS_1 "XCA1dd7JaWhiuBavUM2ZTJG3GdgPkT1Yd5Q6VvNvnxbEfb6JhUhziTF6w5mMPVeoSv3aa1zGyhedpaa2QQtGEjBo7N6av9nhaU"
#define NETWORK_DATA_NODE_PUBLIC_ADDRESS_2 "XCA1b6Sg5QVBX4jrctQ9SVUcHFqpaGST6bqtFpyoQadTX8SaDs92xR8iec3VfaXKzhYijFiMfwoM4TuYRgy6NXzn5titJnWbra"
#define NETWORK_DATA_NODE_PUBLIC_ADDRESS_3 "XCA1UNwXyshf1cuN4LRWxgX84rkoM1fo12AbG7CiuTi27PEuxPicaTfNSA5WtsHHTkZ1GAy4bsd6CXy6ag6YEM9H7oNuBihrzM"
#define NETWORK_DATA_NODE_PUBLIC_ADDRESS_4 "XCA1WDfJTzqLJjn9YgXubf4RnxzUqMrWJaMWQKH8V3tZ9tgtWs5RoXfcHo7vQnZndj7PeyfcUcgkGX6cQNfVrWfC1g2iN84K1w"
#define NETWORK_DATA_NODE_PUBLIC_ADDRESS_5 "XCA1fjt6X5k9CR13Pq1BKpJKLUjmcBCd3NDyhAfVnDvUirv16tmv4gQ4L3MtK1TfBoUdM1d48HN6kZS7NyYWJLmQ8xQiGXsS3z" 
#define NETWORK_DATA_NODE_IP_ADDRESS_1 "xcashseeds.us"
#define NETWORK_DATA_NODE_IP_ADDRESS_2 "xcashseeds.uk"
#define NETWORK_DATA_NODE_IP_ADDRESS_3 "xcashseeds.cc"
#define NETWORK_DATA_NODE_IP_ADDRESS_4 "xcashseeds.com"
#define NETWORK_DATA_NODE_IP_ADDRESS_5 "xcashseeds.net"

#define INITIALIZE_NETWORK_DATA_NODES_LIST const std::vector<std::string> network_data_nodes_list = {NETWORK_DATA_NODE_IP_ADDRESS_1,NETWORK_DATA_NODE_IP_ADDRESS_2,NETWORK_DATA_NODE_IP_ADDRESS_3,NETWORK_DATA_NODE_IP_ADDRESS_4,NETWORK_DATA_NODE_IP_ADDRESS_5}
#define INITIALIZE_NETWORK_DATA_NODES_LIST_STRUCT \
network_data_nodes_list.network_data_nodes_public_address[0] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_1; \
network_data_nodes_list.network_data_nodes_IP_address[0] = NETWORK_DATA_NODE_IP_ADDRESS_1; \
network_data_nodes_list.network_data_nodes_public_address[1] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_2; \
network_data_nodes_list.network_data_nodes_IP_address[1] = NETWORK_DATA_NODE_IP_ADDRESS_2; \
network_data_nodes_list.network_data_nodes_public_address[2] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_3; \
network_data_nodes_list.network_data_nodes_IP_address[2] = NETWORK_DATA_NODE_IP_ADDRESS_3; \
network_data_nodes_list.network_data_nodes_public_address[3] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_4; \
network_data_nodes_list.network_data_nodes_IP_address[3] = NETWORK_DATA_NODE_IP_ADDRESS_4; \
network_data_nodes_list.network_data_nodes_public_address[4] = NETWORK_DATA_NODE_PUBLIC_ADDRESS_5; \
network_data_nodes_list.network_data_nodes_IP_address[4] = NETWORK_DATA_NODE_IP_ADDRESS_5;



#define PER_KB_FEE_QUANTIZATION_DECIMALS        8

#define HASH_OF_HASHES_STEP                     256

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16

// New constants are intended to go here
namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)2000); // 2 * pow(10, 6)
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100); // pow(10, 2)
  std::string const P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

  uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x5c134;
  uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x3fc134;
  uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 42;
  uint16_t const P2P_DEFAULT_PORT = 18280;
  uint16_t const RPC_DEFAULT_PORT = 18281;
  uint16_t const ZMQ_RPC_DEFAULT_PORT = 18282;
  boost::uuids::uuid const NETWORK_ID = {{0x07, 0x10, 0x41, 0x57, 0x48, 0x62, 0x41, 0x65, 0x17, 0x31, 0x00, 0x82, 0x12, 0xA1, 0xA1, 0x11}};
  std::string const GENESIS_TX = "013c01ff0001c0843d02ba9cc057e6e15a5c8e0399d405954253c60a50c5725a3afc256ab8ed5f6386e3210129dc99b9b322e0abb3e59e3eb5a8fd8376b30bd43c9ef5a867f6024049edf57a";
  uint32_t const GENESIS_NONCE = 10000;

  namespace testnet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x16871e;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x17071e;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;
    uint16_t const P2P_DEFAULT_PORT = 28280;
    uint16_t const RPC_DEFAULT_PORT = 28281;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 28282;
    boost::uuids::uuid const NETWORK_ID = { {
        0x10 ,0x10, 0x41, 0x53 , 0x48, 0x62 , 0x41, 0x65, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x91
      } };
    std::string const GENESIS_TX = "013c01ff0001b197bcc5c605029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd0880712101f1dde8d8d6c53e9d2e920d6e66432eaff6a85b2d25043fc29ef477b075b143df";
    uint32_t const GENESIS_NONCE = 10001;
  }

  namespace stagenet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 24;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 36;
    uint16_t const P2P_DEFAULT_PORT = 38080;
    uint16_t const RPC_DEFAULT_PORT = 38081;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 38082;
    boost::uuids::uuid const NETWORK_ID = { {
        0x10 ,0x10, 0x41, 0x53 , 0x48, 0x62 , 0x41, 0x65, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x92
      } };
    std::string const GENESIS_TX = "013c01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b";
    uint32_t const GENESIS_NONCE = 10002;
  }
}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN,
    UNDEFINED = 255
  };
  struct config_t
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t const P2P_DEFAULT_PORT;
    uint16_t const RPC_DEFAULT_PORT;
    uint16_t const ZMQ_RPC_DEFAULT_PORT;
    boost::uuids::uuid const NETWORK_ID;
    std::string const GENESIS_TX;
    uint32_t const GENESIS_NONCE;
  };
  inline const config_t& get_config(network_type nettype)
  {
    static const config_t mainnet = {
      ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::P2P_DEFAULT_PORT,
      ::config::RPC_DEFAULT_PORT,
      ::config::ZMQ_RPC_DEFAULT_PORT,
      ::config::NETWORK_ID,
      ::config::GENESIS_TX,
      ::config::GENESIS_NONCE
    };
    static const config_t testnet = {
      ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::testnet::P2P_DEFAULT_PORT,
      ::config::testnet::RPC_DEFAULT_PORT,
      ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
      ::config::testnet::NETWORK_ID,
      ::config::testnet::GENESIS_TX,
      ::config::testnet::GENESIS_NONCE
    };
    static const config_t stagenet = {
      ::config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::stagenet::P2P_DEFAULT_PORT,
      ::config::stagenet::RPC_DEFAULT_PORT,
      ::config::stagenet::ZMQ_RPC_DEFAULT_PORT,
      ::config::stagenet::NETWORK_ID,
      ::config::stagenet::GENESIS_TX,
      ::config::stagenet::GENESIS_NONCE
    };
    switch (nettype)
    {
      case MAINNET: return mainnet;
      case TESTNET: return testnet;
      case STAGENET: return stagenet;
      case FAKECHAIN: return mainnet;
      default: throw std::runtime_error("Invalid network type");
    }
  };
}
