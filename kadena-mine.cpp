#define _GNU_SOURCE 1

#include "kadena-mine.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "optional.hpp"

namespace kadena {
namespace crypto {
namespace mining {
namespace {
void noop() {}
}  // namespace

nonstd::optional<uint64_t>
parse_results_vector(const uint64_t starting_nonce,
                     const uint8_t* begin,
                     const uint8_t* end) {
  const uint8_t* it = std::find_if(begin, end, [](uint8_t x) { return x != 0; });
  nonstd::optional<uint64_t> out;
  if (it != end) {
    out.emplace(starting_nonce + static_cast<uint64_t>(it - begin));
  }
  return out;
}

mining_synchronization::mining_synchronization()
  : terminate_(term_state::RUNNING),
    winning_nonce_(0),
    next_nonce_(0),
    on_finished_(&noop) {}

void mining_synchronization::reset() {
  terminate_ = term_state::RUNNING;
  winning_nonce_ = 0;
  next_nonce_ = 0;
}

void
mining_synchronization::set_next_nonce(uint64_t x) {
  next_nonce_.store(x);
}

void
mining_synchronization::terminate_success(uint64_t w) {
  winning_nonce_ = w;
  terminate_.store(term_state::SUCCESS);
  auto old = std::atomic_exchange(&terminate_, term_state::SUCCESS);
  if (old == term_state::RUNNING) {
    on_finished_();
  }
}

void mining_synchronization::terminate_cancelled() {
  terminate_ = term_state::CANCELLED;
}

void
mining_synchronization::run_mining_threads(
    int starting_device,
    int num_devices,
    mining_synchronization::thread_proc_t thread_proc) {
  std::vector<std::thread> threads;
  try {
    mining_synchronization* me = this;
    for (int i = starting_device; i < starting_device + num_devices; ++i) {
      threads.emplace_back(
        std::thread([me, &thread_proc, i]() {
                      thread_proc(*me, i);
                    }));
    }
  } catch (...) {
    terminate_cancelled();
    for (auto& t : threads) t.join();
    throw;
  }
  for (auto& t : threads) t.join();
}

mining_stats
mining_session(mining_synchronization& sync,
               uint64_t starting_nonce,
               int starting_device,
               int num_devices,
               mining_synchronization::thread_proc_t thread) {
  mining_stats out;
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  sync.set_next_nonce(starting_nonce);
  sync.run_mining_threads(starting_device, num_devices, thread);
  if (sync.cancelled()) {
    throw std::runtime_error("cancelled.");
  }
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  double elapsed = timespec_subtract(&end_time, &start_time);
  char buf[1024];
  out.winning_nonce = sync.winning_nonce();
  uint64_t num_nonces = out.winning_nonce - starting_nonce;
  sprintf(buf, "Ran %" PRIu64 " hashes in %.2f seconds, rate=%.2f MH/s\n",
          num_nonces, elapsed,
          double(num_nonces) / (1000000.0 * elapsed));
  DBG() << buf;
  out.num_nonces = num_nonces;
  out.elapsed = elapsed;
  return out;
}

unix_domain_server::unix_domain_server(
  std::string p,
  int s,
  int n,
  size_t wg_size,
  unix_domain_server::thread_proc_t t)
  : path_(std::move(p)),
    thread_proc_(std::move(t)),
    starting_device_(s),
    num_devices_(n) {
  sync_.set_nonce_skip(wg_size);
  set_on_fork([](){});
}

unix_domain_server::~unix_domain_server() {
  if (listen_fd_) close(listen_fd_);
  if (event_fd_) close(event_fd_);
}

void unix_domain_server::run() {
  bind();
  accept_loop();
}

static constexpr bool ABSTRACT = true;

void fill_unix_addr(const std::string& p, sockaddr_un& addr) {
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (ABSTRACT) {
    // set first byte 0 -- linux abstract namespace sockets
    strncpy(addr.sun_path + 1, p.c_str(), sizeof(addr.sun_path)-2);
  } else {
    strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path)-1);
  }
  addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
}

void check_sys_error() {
  if (errno) {
    throw std::system_error(std::make_error_code(std::errc(errno)));
  }
}

void unix_domain_server::bind() {
  if (listen_fd_) close(listen_fd_);
  errno = 0;
  listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  check_sys_error();
  struct sockaddr_un addr;
  fill_unix_addr(path_, addr);
  if (!ABSTRACT) {
    unlink(path_.c_str());
    check_sys_error();
  }
  ::bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr));
  check_sys_error();
  listen(listen_fd_, 20);       // we only process one req at a time so let
                                // them pile up if necessary
  check_sys_error();

  event_fd_ = eventfd(0, 0);
}

unix_socket_session::unix_socket_session(int f)
  : fd(f) {}

unix_socket_session::unix_socket_session(unix_socket_session&& o)
  : fd(o.fd) {
  o.clear();
}

unix_socket_session::~unix_socket_session() {
  if (fd) ::close (fd);
  clear();
}

unix_socket_session&
unix_socket_session::operator=(unix_socket_session&& o) {
  fd = o.fd;
  o.clear();
  return *this;
}

void unix_domain_server::accept_loop() {
  struct sockaddr addr;
  socklen_t addrlen = 0;
  auto report_err = [](const std::string& s) {
                      DBG() << "Caught exception in accept loop: "
                            << s
                            << ", continuing.\n";
                    };
  while (true) {
    try {
      int fd = accept(listen_fd_, &addr, &addrlen);
      if (fd < 0) {
        if (errno == EAGAIN || errno == EINTR) {
          errno = 0;
          continue;
        } else {
          perror("accept");
          errno = 0;
          continue;
        }
      }
      DBG() << "accept [" << fd << "]\n";
      sync_.reset();
      handle_request(unix_socket_session(fd));

    } catch (const std::exception& e) {
      report_err(e.what());
    } catch (...) {
      report_err("Unknown exception");
    }
  }
}

static void recv_all(int fd, void* buf, size_t sz) {
  uint8_t* p = (uint8_t*) buf;
  while (sz > 0) {
    ssize_t retval = recv(fd, p, sz, 0);
    if (retval < 0) {
      if (retval == EAGAIN || retval == EINTR || retval == EWOULDBLOCK) continue;
      check_sys_error();
    } else if (retval == 0) {
      throw std::runtime_error("short read (unexpected EOF)");
    } else {
      sz -= retval;
      p += retval;
    }
  }
}

static void send_all(int fd, void* buf, size_t sz) {
  uint8_t* p = (uint8_t*) buf;
  while (sz > 0) {
    ssize_t retval = send(fd, p, sz, 0);
    if (retval < 0) {
      if (retval == EAGAIN || retval == EINTR || retval == EWOULDBLOCK) continue;
      check_sys_error();
    } else if (retval == 0) {
      throw std::runtime_error("short write");
    } else {
      sz -= retval;
      p += retval;
    }
  }
}

void unix_domain_server::handle_request(unix_socket_session session) {
  std::string blockbytes;
  static constexpr size_t BSIZE = sizeof(input_message) + (1 << 16) - 1;
  uint8_t buf[BSIZE];
  input_message* imsg = reinterpret_cast<input_message*>(buf);
  std::string target_hash;
  DBG() << "new session [" << session.fd << "]: reading "
        << sizeof(input_message) << " byte request header\n";
  recv_all(session.fd, buf, sizeof(input_message));
  DBG() << "got header, block has "
        << imsg->bytes_size
        << " bytes\n";
  recv_all(session.fd, &imsg->bytes[0], imsg->bytes_size);

  blockbytes.insert(0, &imsg->bytes[0], imsg->bytes_size);
  target_hash.insert(0, imsg->target_hash, 32);

  DBG() << "Got request of size " << blockbytes.size()
        << " with target hash " << hex_encode_bigendian(target_hash)
        << "\n";

  if (blockbytes.size() < 16) {
    throw std::runtime_error("short input block");
  }

  mining_stats stats_out;
  auto tp = [&](mining_synchronization& s, int t) {
              thread_proc_(target_hash, blockbytes, s, t);
            };
  std::thread t(
    [&]() {
      try {
        stats_out = mining_session(sync_, imsg->starting_nonce, starting_device_,
                                   num_devices_, tp);
      } catch(...) {}
      uint64_t event = 1;
      write(event_fd_, &event, sizeof(uint64_t));
    });
  auto cleanup_thread = make_cleanup(
    [&]() {
      t.join();
      DBG() << "request handler exiting.\n";
    });
  bool ignore_client_socket = false;
  while (true) {
    DBG() << "waiting for activity...\n";
    struct pollfd fds[2];
    fds[0].fd = event_fd_;
    fds[0].events = POLLIN | POLLRDHUP | POLLPRI;
    fds[1].fd = session.fd;
    fds[1].events = POLLIN | POLLRDHUP | POLLPRI;
    int num_fds = ignore_client_socket ? 1 : 2;
    int retval = poll(fds, num_fds, -1);
    if (retval < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        errno = 0; continue;
      }
    } else if (retval == 0) {  // should be impossible?
      continue;
    } else {
      if (fds[0].revents & (POLLHUP | POLLERR | POLLRDHUP | POLLPRI | POLLNVAL)) {
        throw std::runtime_error("what happened to our eventfd??");
      }
      if (fds[0].revents & POLLIN) {
        // event on the eventfd means that mining is complete.
        uint64_t dummy = 0;
        while (true) {
          ssize_t r = read(event_fd_, &dummy, sizeof(uint64_t));
          if (r < 0) {
            if (errno != EAGAIN && errno != EINTR) {
              check_sys_error();
            }
            continue;
          }
          break;
        }
        DBG() << "got mining complete event code "
              << dummy
              << "\n";
        if (!sync_.cancelled()) {
          // ok, we're done. send the response
          DBG() << "mining complete: " << nonce_to_string(stats_out.winning_nonce)
                << " "
		<< std::dec
                << stats_out.num_nonces
                << " "
                << stats_out.elapsed
                << "\n";
          DBG() << "sending response to client socket\n";
          send_all(session.fd, &stats_out, sizeof(stats_out));
          DBG() << "response sent, closing session\n";
        } else {
          DBG() << "cancelled, returning.\n";
        }
        return;
      }
      // activity on some file descriptor
      if (fds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLRDHUP | POLLPRI | POLLNVAL)) {
        // any kind of input/closure/error on socket here can only mean
        // cancellation.
        DBG() << "activity on socket, cancelling\n";
        sync_.terminate_cancelled();
        ignore_client_socket = true;
        // wait for event fd
        continue;
      }
    }
  }
}

unix_domain_client::unix_domain_client(std::string p)
  : path_(std::move(p)) {}

unix_domain_client::~unix_domain_client() {
}

static int g_client_fd = 0;
static void client_fd_sighandler(int signal_no) {
  static char msg[] = "caught signal, bye\n";
  write(1, msg, sizeof(msg));
  if (g_client_fd) {
    // make sure g_client_fd is set nonblocking so we don't stall here
    int flags = fcntl(g_client_fd, F_GETFL, 0);
    if (flags != -1) {
      flags = flags | O_NONBLOCK;
      if (fcntl(g_client_fd, F_SETFL, flags) == 0) {
        shutdown(g_client_fd, SHUT_WR);
        ::close(g_client_fd);
      }
    }
  }
  // set default handler and re-raise
  signal(signal_no, SIG_DFL);
  raise(signal_no);
}

mining_stats unix_domain_client::run(const std::string& target_hash,
                                     const std::string& blockbytes,
                                     uint64_t starting_nonce) {
  struct sockaddr_un addr;
  fill_unix_addr(path_, addr);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    check_sys_error();
  }
  auto cleanup_fd = make_cleanup(
    [fd]() {
      ::close(fd);
      g_client_fd = 0;
    });
  g_client_fd = fd;
  signal(SIGTERM, &client_fd_sighandler);
  signal(SIGINT, &client_fd_sighandler);
  DBG() << "connecting to " << path_ << "\n";
  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    check_sys_error();
  }

  if (target_hash.size() != 32) {
    std::string msg = "Bad target hash: ";
    msg += hex_encode_bigendian(target_hash);
    throw std::runtime_error(std::move(msg));
  }
  size_t nbytes = sizeof(unix_domain_server::input_message)
    + blockbytes.size();
  std::vector<uint8_t> bytes(nbytes, uint8_t{0});
  unix_domain_server::input_message *msg =
    (unix_domain_server::input_message*) bytes.data();
  msg->starting_nonce = starting_nonce;
  msg->bytes_size = blockbytes.size();
  memcpy(msg->target_hash, target_hash.data(), 32);
  memcpy(msg->bytes, blockbytes.data(), blockbytes.size());
  DBG() << "sending " << nbytes << " bytes of mining request...\n";
  send_all(fd, msg, nbytes);
  DBG() << "reading response...\n";
  mining_stats out;
  recv_all(fd, &out, sizeof(mining_stats));
  return out;
}

}  // namespace mining

namespace {
inline char from_hex(char c) {
  char out = 0;
  if (c >= '0' && c <= '9') out = c - '0';
  else if (c >= 'a' && c <= 'f') out = 10 + c - 'a';
  else if (c >= 'A' && c <= 'F') out = 10 + c - 'A';
  return out;
}

std::string get_time() {
  auto now = time(nullptr);
  char buf[256];
  (void) ctime_r(&now, buf);
  for (char* p = buf; p < buf + sizeof(buf); ++p) {
    if (*p == '\n') {
      *p = 0; break;
    } else if (*p == 0) break;
  }
  return std::string{buf};
}
}  // namespace

std::string hex_decode(const std::string& input) {
  const size_t n = input.size();
  std::string out(n / 2, '\0');
  if (n > 0) {
    size_t j = 0;
    for (size_t i = 0; i < n - 1; i += 2) {
      char hi = from_hex(input[i]);
      char lo = from_hex(input[i + 1]);
      char c = (hi << 4) | lo;
      out[j++] = c;
    }
  }
  return out;
}

std::string hex_encode_bigendian(const std::string& input) {
  std::ostringstream ss;
  static char table[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                          'a', 'b', 'c', 'd', 'e', 'f' };
  for (auto it = input.rbegin(); it != input.rend(); ++it) {
    unsigned char c = *it;
    unsigned char lo = c & 0xf;
    unsigned char hi = (c >> 4) & 0xf;
    ss << table[hi] << table[lo];
  }
  return ss.str();
}

#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

uint64_t parse_nonce(const std::string& s) {
  if (s.size() != 16) {
    throw std::runtime_error("bad nonce");
  }
  std::string dehex = hex_decode(s);
  uint64_t x = *((uint64_t*) dehex.data());
  return ntohll(x);
}

std::string slurp_input(std::istream& is) {
  std::stringstream ss;
  ss << is.rdbuf();
  return ss.str();
}

static bool g_timestamps = true;

void set_debug_timestamps(bool t) { g_timestamps = t; }

std::ostream& DBG() {
  if (g_timestamps) {
    std::cerr << '[' << get_time() << "]: ";
  }
  return std::cerr;
}

std::string nonce_to_string(uint64_t out_nonce) {
  char buf[32];
  sprintf(buf, "%016" PRIx64, out_nonce);
  return std::string{buf};
}

void
print_out_nonce(uint64_t out_nonce, uint64_t nonces_tried, uint64_t hash_rate) {
  printf("%016" PRIx64 "\t%" PRIu64 "\t%" PRIu64 "\n",
         out_nonce, nonces_tried, hash_rate);
}

srand48_seeder::srand48_seeder() {
    srand48(time(NULL));
}

double
timespec_subtract (struct timespec *x, struct timespec *y)
{
  struct timespec result;
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int64_t nsec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
    y->tv_nsec -= 1000000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_nsec - y->tv_nsec > 1000000000) {
    int64_t nsec = (x->tv_nsec - y->tv_nsec) / 1000000000;
    y->tv_nsec += 1000000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_nsec is certainly positive. */
  result.tv_sec = x->tv_sec - y->tv_sec;
  result.tv_nsec = x->tv_nsec - y->tv_nsec;

  return ((1000000000.0 * result.tv_sec) + double(result.tv_nsec)) / 1000000000.0;
}

uint64_t random_nonce() {
  auto r = []() -> uint32_t {
             return static_cast<uint32_t>(mrand48());
           };
  const uint64_t nonce_a = r();
  const uint64_t nonce_b = r();
  return (nonce_a << 32) | nonce_b;
}

}  // namespace crypto
}  // namespace kadena
