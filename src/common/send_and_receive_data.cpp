#include "common/send_and_receive_data.h"
#include "common/blocking_tcp_client.h"

namespace xcash_net {

static bool is_ipv4_literal(const std::string& s) {
  struct in_addr a{};
  return inet_pton(AF_INET, s.c_str(), &a) == 1;
}

// trim plain ASCII whitespace (guards against CR/LF/space around host)
static void trim_ascii_ws(std::string& s) {
  auto isws = [](unsigned char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; };
  auto b = std::find_if_not(s.begin(), s.end(), isws);
  auto e = std::find_if_not(s.rbegin(), s.rend(), isws).base();
  s = (b < e) ? std::string(b, e) : std::string();
}

std::string send_and_receive_data(std::string IP_address,
                                  std::string data2,
                                  int send_or_receive_socket_data_timeout_settings)
{
  // ---- Config ----
  static constexpr size_t kMaxRespBytes = 256 * 1024; // guardrail
  const int connect_timeout_ms = CONNECTION_TIMEOUT_SETTINGS;
  const int io_timeout_ms      = send_or_receive_socket_data_timeout_settings;

  // ---- Helpers ----
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

  // ---- sanitize host ----
  trim_ascii_ws(IP_address);

  // ---- Connect (numeric IPv4 fast-path or DNS path) ----
  int sock = -1;

  if (is_ipv4_literal(IP_address)) {
    // Direct numeric IPv4 connect
    sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "0|SOCKET_FAIL";

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in sa{}; sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)strtoul(SEND_DATA_PORT, nullptr, 10));

    if (inet_pton(AF_INET, IP_address.c_str(), &sa.sin_addr) != 1) {
      ::close(sock); return "0|BAD_IPV4";
    }

    int rc = ::connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) { ::close(sock); return "0|CONNECT_FAIL"; }

    long long deadline = now_ms() + connect_timeout_ms;
    if (!wait_writable(sock, deadline)) { ::close(sock); return "0|CONNECT_TIMEOUT"; }

    int err = 0; socklen_t elen = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
      ::close(sock); return std::string("0|CONNECT_ERR:") + std::to_string(err);
    }

    if (flags >= 0) fcntl(sock, F_SETFL, flags); // back to blocking
  } else {
    // Hostname / IPv6 via getaddrinfo
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICSERV; // port is numeric
    addrinfo* res = nullptr;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%s", SEND_DATA_PORT);


    int gai = getaddrinfo(IP_address.c_str(), portstr, &hints, &res);
    if (gai != 0) return std::string("0|DNS_FAIL:") + gai_strerror(gai);
    int last_err = 0;

    for (addrinfo* rp = res; rp; rp = rp->ai_next) {
      sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock < 0) { last_err = errno; continue; }

      int flags = fcntl(sock, F_GETFL, 0);
      if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

      int rc = ::connect(sock, rp->ai_addr, rp->ai_addrlen);
      if (rc < 0 && errno != EINPROGRESS) { last_err = errno; ::close(sock); sock = -1; continue; }

      long long deadline = now_ms() + connect_timeout_ms;
      if (!wait_writable(sock, deadline)) { ::close(sock); sock = -1; last_err = ETIMEDOUT; continue; }

      int err = 0; socklen_t elen = sizeof(err);
      if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
        ::close(sock); sock = -1; last_err = err ? err : errno; continue;
      }

      if (flags >= 0) fcntl(sock, F_SETFL, flags); // back to blocking
      break; // connected
    }
    freeaddrinfo(res);
    if (sock < 0) {
      if (last_err == ETIMEDOUT) return "0|CONNECT_TIMEOUT";
      return std::string("0|CONNECT_ERR:") + std::to_string(last_err ? last_err : -1);
    }
  }

  // Optional: also set SO_SNDTIMEO/SO_RCVTIMEO (select already enforces deadlines)
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
      return e; // "0|WRITE_TIMEOUT" / "0|WRITE_FAIL"
    }
  }

  // ---- RECV: 4-byte big-endian length, then payload ----
  long long read_deadline = now_ms() + io_timeout_ms;

  uint32_t be_len = 0;
  if (auto e = recv_exact(sock, &be_len, sizeof(be_len), read_deadline, /*prefix*/true); !e.empty()) {
    ::close(sock);
    return e; // "0|READ_TIMEOUT_PREFIX" / "0|READ_FAIL_PREFIX" / "0|PEER_CLOSED"
  }

  uint32_t reply_len = ntohl(be_len);
  if (reply_len == 0) { ::close(sock); return "0|BAD_LENGTH_0"; }
  if (reply_len > kMaxRespBytes) { ::close(sock); return "0|TOO_LARGE"; }

  std::string response_string(reply_len, '\0');
  if (auto e = recv_exact(sock, &response_string[0], reply_len, read_deadline); !e.empty()) {
    ::close(sock);
    return e; // "0|READ_TIMEOUT" / "0|READ_FAIL" / "0|PEER_CLOSED"
  }

  ::close(sock);
  return response_string; // success
}

}