#include "common/send_and_receive_data.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/tcp.hpp>

using boost::asio::ip::tcp;

namespace {

// Small helper to run one async op with a timeout.
template <typename Initiation>
static boost::system::error_code run_with_timeout(boost::asio::io_context& ioc,
                                                  std::chrono::milliseconds timeout,
                                                  Initiation&& initiate)
{
  boost::system::error_code ec;
  boost::asio::steady_timer timer{ioc};
  std::atomic<bool> done{false};

  if (timeout.count() > 0) {
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& tec){
      if (!tec && !done.load(std::memory_order_relaxed)) {
        ioc.stop(); // cancel pending ops by stopping the context
      }
    });
  }

  initiate([&](const boost::system::error_code& e){
    ec = e;
    done.store(true, std::memory_order_relaxed);
    timer.cancel(); // stop the timer if op finished first
  });

  ioc.restart();
  ioc.run();
  return ec; // default-constructed == success
}

inline void trim_ascii_ws(std::string& s)
{
  auto isws = [](unsigned char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; };
  auto b = std::find_if_not(s.begin(), s.end(), isws);
  auto e = std::find_if_not(s.rbegin(), s.rend(), isws).base();
  s = (b < e) ? std::string(b, e) : std::string();
}

} // namespace

namespace xcash_net {

std::string send_and_receive_data(std::string IP_address,
                                  std::string data2,
                                  int send_or_receive_socket_data_timeout_settings)
{
  // ---- sanitize host ----
  trim_ascii_ws(IP_address);

  // Prepare io_context
  boost::asio::io_context ioc;

  // Resolve host:port (use SEND_DATA_PORT from cryptonote_config.h)
  tcp::resolver resolver{ioc};
  tcp::resolver::results_type endpoints;

  {
    auto init = [&](auto handler){
      resolver.async_resolve(IP_address, SEND_DATA_PORT,
        [&, handler](const boost::system::error_code& e, tcp::resolver::results_type r){
          if (!e) endpoints = std::move(r);
          handler(e);
        });
    };
    auto ec = run_with_timeout(ioc, std::chrono::milliseconds(CONNECTION_TIMEOUT_SETTINGS), init);
    if (ec) {
      if (ec == boost::asio::error::operation_aborted) return "0|DNS_TIMEOUT";
      return "0|DNS_FAIL";
    }
  }

  // Connect
  tcp::socket sock{ioc};
  {
    auto init = [&](auto handler){
      boost::asio::async_connect(sock, endpoints,
        [handler](const boost::system::error_code& e, const tcp::endpoint&){ handler(e); });
    };
    auto ec = run_with_timeout(ioc, std::chrono::milliseconds(CONNECTION_TIMEOUT_SETTINGS), init);
    if (ec) {
      if (ec == boost::asio::error::operation_aborted) return "0|CONNECT_TIMEOUT";
      return "0|CONNECT_FAIL";
    }
  }

  // Send payload
  {
    auto init = [&](auto handler){
      boost::asio::async_write(sock, boost::asio::buffer(data2),
        [handler](const boost::system::error_code& e, std::size_t){ handler(e); });
    };
    auto ec = run_with_timeout(ioc, std::chrono::milliseconds(send_or_receive_socket_data_timeout_settings), init);
    if (ec) {
      if (ec == boost::asio::error::operation_aborted) return "0|WRITE_TIMEOUT";
      return "0|WRITE_FAIL";
    }
  }

  // Read 4-byte big-endian length
  uint32_t be_len = 0;
  {
    auto init = [&](auto handler){
      boost::asio::async_read(sock, boost::asio::buffer(&be_len, sizeof(be_len)),
        [handler](const boost::system::error_code& e, std::size_t){ handler(e); });
    };
    auto ec = run_with_timeout(ioc, std::chrono::milliseconds(send_or_receive_socket_data_timeout_settings), init);
    if (ec) {
      if (ec == boost::asio::error::operation_aborted) return "0|READ_TIMEOUT_PREFIX";
      if (ec == boost::asio::error::eof)            return "0|PEER_CLOSED";
      return "0|READ_FAIL_PREFIX";
    }
  }

  const uint32_t len = ntohl(be_len);
  if (len == 0)               return "0|BAD_LENGTH_0";
  if (len > 256 * 1024u)      return "0|TOO_LARGE";

  // Read body
  std::string response(len, '\0');
  {
    auto init = [&](auto handler){
      boost::asio::async_read(sock, boost::asio::buffer(response.data(), response.size()),
        [handler](const boost::system::error_code& e, std::size_t){ handler(e); });
    };
    auto ec = run_with_timeout(ioc, std::chrono::milliseconds(send_or_receive_socket_data_timeout_settings), init);
    if (ec) {
      if (ec == boost::asio::error::operation_aborted) return "0|READ_TIMEOUT";
      if (ec == boost::asio::error::eof)               return "0|PEER_CLOSED";
      return "0|READ_FAIL";
    }
  }

  return response; // success
}

} // namespace xcash_net