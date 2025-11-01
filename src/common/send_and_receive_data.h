#pragma once

#include <boost/version.hpp>

#if BOOST_VERSION >= 106600
  // Modern Boost.Asio (no io_service/deadline_timer headers)
  #include <boost/asio/io_context.hpp>
  #include <boost/asio/steady_timer.hpp>
  namespace boost { namespace asio {
    using io_service     = io_context;   // keep old name alive
    using deadline_timer = steady_timer; // keep old name alive
  }}
#else
  // Legacy Boost.Asio
  #include <boost/asio/io_service.hpp>
  #include <boost/asio/deadline_timer.hpp>
#endif

#include <thread>
#include <future>
#include <algorithm>
#include <cstdio>
#include <cmath>
#include <stdlib.h>
#include <fstream>
#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/asio.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/thread.hpp>

#include <boost/asio/connect.hpp>
// #include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/write.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

// using boost::asio::deadline_timer;
// using boost::asio::ip::tcp;

#include "cryptonote_config.h"

std::string send_and_receive_data(std::string IP_address,std::string data2, int send_or_receive_socket_data_timeout_settings = SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS);