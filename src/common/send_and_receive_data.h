#pragma once

#include <boost/version.hpp>

#if BOOST_VERSION >= 106600
  #include <boost/asio/io_context.hpp>
  #include <boost/asio/steady_timer.hpp>
  namespace xasio {
    using io_service     = boost::asio::io_context;
    using deadline_timer = boost::asio::steady_timer;
  }
#else
  #include <boost/asio/io_service.hpp>
  #include <boost/asio/deadline_timer.hpp>
  namespace xasio {
    using io_service     = boost::asio::io_service;
    using deadline_timer = boost::asio::deadline_timer;
  }
#endif

#include <thread>
#include <future>
#include <algorithm>
#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>

// Include generic Asio AFTER the compat block
#include <boost/asio.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/thread.hpp>

#include <boost/asio/connect.hpp>
// DO NOT include the removed header:
// #include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/write.hpp>
#include <iostream>
#include <string>

// Bring in the aliases you want to use locally:
using xasio::deadline_timer;
using xasio::io_service;           // only if you use io_service in this file
using boost::asio::ip::tcp;

#include "cryptonote_config.h"

std::string send_and_receive_data(std::string IP_address,
                                  std::string data2,
                                  int send_or_receive_socket_data_timeout_settings = SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS);
                                  