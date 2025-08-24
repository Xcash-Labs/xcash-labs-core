#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <memory> // For std::shared_ptr


#include "common/send_and_receive_data.h"
#include "common/blocking_tcp_client.h"
#include "send_and_receive_data.h"


std::string send_and_receive_data__OLD__(std::string IP_address,std::string data2, int send_or_receive_socket_data_timeout_settings)
{
  // Variables
  std::string response_string;
  auto connection_timeout = boost::posix_time::milliseconds(CONNECTION_TIMEOUT_SETTINGS);
  auto send_and_receive_data_timeout = boost::posix_time::milliseconds(send_or_receive_socket_data_timeout_settings);

  try
  {
    client c;
    c.connect(IP_address, SEND_DATA_PORT, connection_timeout);
    
    // send the message and read the response
    c.write_line(data2, send_and_receive_data_timeout);
    response_string = c.read_until('}', send_and_receive_data_timeout);
  }
  catch (std::exception &ex)
  {
    return "0";
  } 
  return response_string;
}










// Drop-in replacement:
//  - SEND: raw payload (no length prefix)
//  - RECV: expect 4-byte big-endian length, then exact payload
//
// Requires: <sys/socket.h> <netdb.h> <unistd.h> <fcntl.h> <arpa/inet.h>
//           <errno.h> <string.h> <time.h> <string> <vector> <algorithm>

std::string send_and_receive_data(std::string IP_address,
                                  std::string data2,
                                  int send_or_receive_socket_data_timeout_settings)
{
  static constexpr size_t kMaxRespBytes = 256 * 1024; // guardrail
  const int connect_timeout_ms = CONNECTION_TIMEOUT_SETTINGS;
  const int io_timeout_ms      = send_or_receive_socket_data_timeout_settings;

  auto now_ms = []() -> long long {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
  };

  auto wait_writable = [&](int fd, long long deadline_ms) -> bool {
    while (true) {
      long long remain = deadline_ms - now_ms();
      if (remain <= 0) return false;
      struct timeval tv{ (int)(remain/1000), (int)((remain%1000)*1000) };
      fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
      int rc = select(fd+1, nullptr, &wfds, nullptr, &tv);
      if (rc > 0) return true;
      if (rc == 0) return false;
      if (errno == EINTR) continue;
      return false;
    }
  };
  auto wait_readable = [&](int fd, long long deadline_ms) -> bool {
    while (true) {
      long long remain = deadline_ms - now_ms();
      if (remain <= 0) return false;
      struct timeval tv{ (int)(remain/1000), (int)((remain%1000)*1000) };
      fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
      int rc = select(fd+1, &rfds, nullptr, nullptr, &tv);
      if (rc > 0) return true;
      if (rc == 0) return false;
      if (errno == EINTR) continue;
      return false;
    }
  };

  auto send_all = [&](int fd, const void* buf, size_t len, long long deadline_ms) -> std::string {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < len) {
      if (!wait_writable(fd, deadline_ms)) return "0|WRITE_TIMEOUT";
      ssize_t n = ::send(fd, p + sent, len - sent,
#ifdef MSG_NOSIGNAL
                         MSG_NOSIGNAL
#else
                         0
#endif
      );
      if (n > 0) { sent += (size_t)n; continue; }
      if (n < 0 && errno == EINTR) continue;
      return "0|WRITE_FAIL";
    }
    return ""; // ok
  };

  auto recv_exact = [&](int fd, void* buf, size_t len, long long deadline_ms, bool prefix=false) -> std::string {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < len) {
      if (!wait_readable(fd, deadline_ms)) return prefix ? "0|READ_TIMEOUT_PREFIX" : "0|READ_TIMEOUT";
      ssize_t n = ::recv(fd, p + got, len - got, 0);
      if (n > 0) { got += (size_t)n; continue; }
      if (n == 0) return "0|PEER_CLOSED";
      if (n < 0 && errno == EINTR) continue;
      return prefix ? "0|READ_FAIL_PREFIX" : "0|READ_FAIL";
    }
    return ""; // ok
  };

  // ---- resolve & connect (nonblocking with timeout) ----
  int sock = -1;
  addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
  addrinfo* res = nullptr;
  char portstr[16]; snprintf(portstr, sizeof portstr, "%d", SEND_DATA_PORT);

  std::cerr << "**********IP_address:      " << IP_address.c_str() << std::endl;

  if (getaddrinfo(IP_address.c_str(), portstr, &hints, &res) != 0)
    return "0|DNS_FAIL";

  for (addrinfo* rp = res; rp; rp = rp->ai_next) {
    sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock < 0) continue;

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int rc = ::connect(sock, rp->ai_addr, rp->ai_addrlen);
    if (rc < 0 && errno != EINPROGRESS) { ::close(sock); sock = -1; continue; }

    long long deadline = now_ms() + connect_timeout_ms;
    if (!wait_writable(sock, deadline)) { ::close(sock); sock = -1; continue; }

    int err = 0; socklen_t elen = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
      ::close(sock); sock = -1; continue;
    }

    // back to blocking
    if (flags >= 0) fcntl(sock, F_SETFL, flags);
    break;
  }
  freeaddrinfo(res);
  if (sock < 0) return "0|CONNECT_TIMEOUT";

  // Optional: set R/W timeouts too (select already enforces deadlines)
  struct timeval tv;
  tv.tv_sec  = io_timeout_ms / 1000;
  tv.tv_usec = (io_timeout_ms % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  // ---- SEND: raw payload ----
  {
    long long write_deadline = now_ms() + io_timeout_ms;
    if (auto e = send_all(sock, data2.data(), data2.size(), write_deadline); !e.empty()) {
      ::close(sock);
      return e;
    }
  }

  // ---- RECV: 4-byte big-endian length, then payload ----
  long long read_deadline = now_ms() + io_timeout_ms;

  uint32_t be_len = 0;
  if (auto e = recv_exact(sock, &be_len, sizeof(be_len), read_deadline, /*prefix*/true); !e.empty()) {
    ::close(sock);
    return e;
  }
  uint32_t reply_len = ntohl(be_len);
  if (reply_len == 0) { ::close(sock); return "0|BAD_LENGTH_0"; }
  if (reply_len > kMaxRespBytes) { ::close(sock); return "0|TOO_LARGE"; }

  std::string response_string(reply_len, '\0');
  if (auto e = recv_exact(sock, &response_string[0], reply_len, read_deadline); !e.empty()) {
    ::close(sock);
    return e;
  }

  ::close(sock);
  return response_string;
}


















namespace xcash_net {
// Function to send a message and receive a reply from a single server asynchronously
void xcash_send_msg_async(
    const std::string& server,
    const std::string& port,
    const std::string& message,
    boost::asio::io_context& io_context,
    std::vector<XcashResult>* results,
    std::function<void()> on_complete,
    const std::string& message_ender = "|END|"
) {
    auto socket = std::make_shared<tcp::socket>(io_context);
    auto timer = std::make_shared<boost::asio::steady_timer>(io_context);
    auto reply_buffer = std::make_shared<boost::asio::streambuf>();
    auto result = std::make_shared<XcashResult>();

    result->server_info = server + ":" + port;

    const std::string xcash_message = message + "|END|";

    try {
        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(server, port);
    
        // Start timer for timeout
        timer->expires_after(std::chrono::milliseconds(300));
        timer->async_wait([=](const boost::system::error_code& ec) mutable {
            if (!ec) {
                socket->close(); // Timeout occurred
                result->reply = "Error: Connection Timeout occurred";
                results->push_back(*result);
                on_complete();
            }
        });


        // Start connection
        socket->async_connect(*endpoints.begin(), [=](const boost::system::error_code& ec) mutable {
            timer->cancel(); // Cancel timer on successful connection

            if (ec) {
                result->reply = "Error: " + ec.message();
                results->push_back(*result);
                on_complete();
                return;
            }

            timer->expires_after(std::chrono::milliseconds(600));
            timer->async_wait([=](const boost::system::error_code& ec) mutable {
                if (!ec) {
                    socket->close(); // Timeout occurred
                    result->reply = "Error: Write Timeout occurred";
                    results->push_back(*result);
                    on_complete();
                }
            });

            // Send message
            boost::asio::async_write(*socket, boost::asio::buffer(xcash_message), [=](const boost::system::error_code& ec, std::size_t) mutable {
                timer->cancel(); // Cancel timer on successful read
                if (ec) {
                    result->reply = "Error: " + ec.message();
                    results->push_back(*result);
                    on_complete();
                    return;
                }

                // Start timer for timeout
                timer->expires_after(std::chrono::seconds(6));
                timer->async_wait([=](const boost::system::error_code& ec) mutable {
                    if (!ec) {
                        socket->close(); // Timeout occurred
                        result->reply = "Error: Read Timeout occurred";
                        results->push_back(*result);
                        on_complete();
                    }
                });

                // Receive reply
                boost::asio::async_read_until(*socket, *reply_buffer, message_ender, [=](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
                    timer->cancel(); // Cancel timer on successful read
                    if (!ec) {
                        result->reply = std::string(boost::asio::buffers_begin(reply_buffer->data()),
                                                    boost::asio::buffers_begin(reply_buffer->data()) + bytes_transferred);
                    } else {
                        result->reply = "Error: " + ec.message();
                    }
                    results->push_back(*result);
                    on_complete();
                });
            });
        });
    } catch (const std::exception& ex) {
        result->reply = "Error: " + std::string(ex.what());
        results->push_back(*result);
        on_complete();
    }
}


void xcash_send_multi_msg_async(
    const std::vector<std::string>& servers,
    const std::string& message,
    std::vector<XcashResult>* results,
    const std::string& message_ender = "|END|"
    ) {
    boost::asio::io_context io_context;
    std::size_t pending_operations = servers.size();
    std::vector<XcashResult> all_results;

    if (servers.empty()) {
        std::cerr << "Error: No servers provided." << std::endl;
        return;
    }
    bool all_done = false;

    // Completion handler
    auto on_complete = [&]() {
        if (--pending_operations == 0) {
            all_done = true;
            io_context.stop();
        }
    };

    // Start sending messages asynchronously
    for (const auto& server : servers) {
        xcash_send_msg_async(server, "18283", message, io_context, &all_results, on_complete, message_ender);
    }

    io_context.run();
    while (!all_done) {
        // io_context.run_one(); // Run only one asynchronous operation at a time
        // Optionally, add a small delay to avoid tight looping
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    for (auto result : all_results) {
    // std::cout << "Server: " << result.server_info << "\n";
    if (result.reply.rfind("Error:", 0) != 0) {
        // Remove message ender
        if (result.reply.size() >= message_ender.size() && 
            result.reply.compare(result.reply.size() - message_ender.size(), message_ender.size(), message_ender) == 0) {
            result.reply.erase(result.reply.size() - message_ender.size());
    
            results->push_back(result);
        }
        // std::cout << "Reply: " << result.reply << "\n";
    }else{
        // std::cout << result.server_info << " : " << result.reply << "\n";
    }
}

}

std::vector<std::string> extract_block_verifiers_IP_address_list(const std::string& message) {
    std::vector<std::string> ip_list;
    std::string key = "block_verifiers_IP_address_list";
    std::size_t start_pos = message.find(key);

    if (start_pos != std::string::npos) {
        start_pos = message.find(":", start_pos + key.length());
        start_pos = message.find("\"", start_pos + 1);
        std::size_t end_pos = message.find("\"", start_pos + 1);
        if (start_pos != std::string::npos && end_pos != std::string::npos) {
            std::string ip_list_str = message.substr(start_pos + 1, end_pos - start_pos - 1);
            std::stringstream ss(ip_list_str);
            std::string ip;
            while (std::getline(ss, ip, '|')) {
                ip_list.push_back(ip);
            }
        }
    }

    return ip_list;
}


void get_block_hashes(std::size_t block_height, std::vector<std::string>& servers, std::vector<std::string>& hashes) {
    std::string message_str = "{\r\n \"message_settings\": \"XCASH_GET_BLOCK_HASH\",\r\n\"block_height\": " + std::to_string(block_height) + "\r\n}";

    std::vector<XcashResult> results;
    xcash_send_multi_msg_async(servers, message_str, &results);

    // Populate the cache with the results
    for (const auto& result : results) {
        if (!result.reply.empty()) {
            std::size_t start_pos = result.reply.find("\"block_hash\":\"");
            if (start_pos != std::string::npos) {
                start_pos += std::string("\"block_hash\":\"").length();
                std::size_t end_pos = result.reply.find("\"", start_pos);
                if (end_pos != std::string::npos) {
                    std::string hash = result.reply.substr(start_pos, end_pos - start_pos);
                    hashes.push_back({hash});
                }
            }
        }
    }
}

} // namespace xcash_net