#pragma once

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "optional.hpp"

namespace kadena {
namespace crypto {
namespace mining {

class mining_synchronization {
public:
  mining_synchronization();
  ~mining_synchronization() = default;
  mining_synchronization(mining_synchronization&&) = delete;
  mining_synchronization(const mining_synchronization&) = delete;

  void set_next_nonce(uint64_t next);
  inline void set_nonce_skip(uint64_t n) { nonce_skip_ = n; }
  inline uint64_t next_nonce() {
    return next_nonce_.fetch_add(nonce_skip_);
  }

  void terminate_success(uint64_t winning_nonce);
  void terminate_cancelled();
  void reset();

  using thread_num_t = int;
  using thread_proc_t = std::function<
      void (mining_synchronization&, thread_num_t)>;
  void run_mining_threads(int starting_device, int num_devices,
                          thread_proc_t thread_proc);

  inline void set_on_finished(std::function<void()> f) {
    on_finished_ = std::move(f);
  }

  inline bool finished() {
    return terminate_.load() != term_state::RUNNING;
  }

  inline bool cancelled() {
    return terminate_.load() == term_state::CANCELLED;
  }

  inline uint64_t winning_nonce() {
    return winning_nonce_.load();
  }

private:
  enum class term_state {
    RUNNING = 0,
    SUCCESS,
    CANCELLED
  };

  std::atomic<term_state> terminate_;
  std::atomic<uint64_t> winning_nonce_;
  std::atomic<uint64_t> next_nonce_;
  std::mutex mu_;
  int nonce_skip_ = 128;
  std::function<void()> on_finished_;
};

struct mining_stats {
  uint64_t winning_nonce = 0;
  uint64_t num_nonces = 0;
  double elapsed = 0.0;
};

mining_stats
mining_session(mining_synchronization& sync,
               uint64_t starting_nonce,
               int starting_device,
               int num_devices,
               mining_synchronization::thread_proc_t thread);

struct unix_socket_session {
  int fd = 0;

  unix_socket_session(int f);
  unix_socket_session(unix_socket_session&& o);
  unix_socket_session(const unix_socket_session&) = delete;
  ~unix_socket_session();
  unix_socket_session& operator=(unix_socket_session&& o);
  inline void clear() {
    fd = 0;
  }
  inline void close() { ::close(fd); fd = 0; }
};

class unix_domain_server {
public:
  using thread_proc_t = std::function<
      void (const std::string&, const std::string&, mining_synchronization&, int)>;
  unix_domain_server(std::string path,
                     int starting_device,
                     int num_devices,
                     size_t workgroup_size,
                     thread_proc_t thread);
  ~unix_domain_server();
  void run();

  struct input_message {
    uint64_t starting_nonce = 0;
    char target_hash[32];
    uint16_t bytes_size = 0;
    char bytes[0];
  } __attribute__((packed));

  void set_on_fork(std::function<void ()> on_fork) {
    on_fork_ = std::move(on_fork);
  }
private:
  void accept_loop();
  void bind();
  void handle_request(unix_socket_session session);

  mining_synchronization sync_;
  std::string path_;
  int listen_fd_ = 0;
  int event_fd_ = 0;
  thread_proc_t thread_proc_;
  int starting_device_ = 0;
  int num_devices_ = 0;

  std::function<void ()> on_fork_;
};

void fill_unix_addr(const std::string& p, sockaddr_un& addr);
void check_sys_error();

class unix_domain_client {
public:
  unix_domain_client(std::string path);
  ~unix_domain_client();

  mining_stats run(const std::string& target_hash,
                   const std::string& blockbytes,
                   uint64_t starting_nonce);

private:
  std::string path_;
};

}  // namespace mining

template <typename T> class cleanup {
public:
  cleanup(T t) : t_(std::move(t)) {}
  cleanup(cleanup&&) = default;
  cleanup(cleanup&) = delete;
  ~cleanup() { t_(); }
private:
  T t_;
};

template <typename T>
cleanup<T> make_cleanup(T t) {
  return cleanup<T>(std::move(t));
}

struct srand48_seeder {
  srand48_seeder();
};

//----------------------------------------------------------------------------
std::string hex_decode(const std::string& input);
std::string hex_encode_bigendian(const std::string& input);
std::string slurp_input(std::istream& is);
void set_debug_timestamps(bool t);
std::ostream& DBG();
std::string nonce_to_string(uint64_t out_nonce);
void print_out_nonce(uint64_t out_nonce, uint64_t nonces_tried,
                     uint64_t hash_rate);
uint64_t parse_nonce(const std::string& s);
double timespec_subtract (struct timespec *x, struct timespec *y);
uint64_t random_nonce();
namespace mining {
nonstd::optional<uint64_t>
parse_results_vector(const uint64_t starting_nonce,
                     const uint8_t* begin,
                     const uint8_t* end);


template <typename Options, typename Usage, typename F>
void run_immediate_mode(int argc, char** argv, const Options& options,
                        Usage usage, F cpu_thread) {
  if (options.target_hash.empty()) {
    DBG() << "Error: must supply target hash. \n\n";
    usage(argv);
  } else {
    DBG() << "Read target hash of "
          << hex_encode_bigendian(options.target_hash)
          << ".\n";
  }

  mining_synchronization sync;

  std::string blockbytes = slurp_input(std::cin);
  DBG() << "Read " << blockbytes.size() << " bytes of input.\n";
  if (blockbytes.size() <= 8) {
    throw std::runtime_error("Input too short for mining.");
  }

  sync.set_nonce_skip(options.global_workgroup_size);
  auto stats = mining_session(
    sync, *options.starting_nonce, options.starting_device, options.num_devices,
    [&](mining_synchronization& s, int d) {
      cpu_thread(options, options.target_hash, blockbytes, s, d);
    });
  print_out_nonce(sync.winning_nonce(), stats.num_nonces,
                  static_cast<uint64_t>(
                    static_cast<double>(stats.num_nonces) / stats.elapsed));
  exit(0);
}

template <typename Options, typename F>
void run_server_mode(const Options& options, F cpu_thread) {
  using namespace kadena::crypto;
  using namespace kadena::crypto::mining;
  mining_synchronization sync;
  DBG() << "Kadena CUDA miner: starting\n";
  unix_domain_server server(
    options.unix_socket_namespace,
    options.starting_device,
    options.num_devices,
    options.global_workgroup_size,
    [&](const std::string& target_hash, const std::string& blockbytes,
        mining_synchronization& s, int d) {
      cpu_thread(options, target_hash, blockbytes, s, d);
    });
  server.run();
}

template <typename Options, typename F, typename Usage>
void run_client_mode(int argc, char** argv, const Options& options,
                     Usage usage, F cpu_thread) {
  if (options.target_hash.empty()) {
    DBG() << "Error: must supply target hash. \n\n";
    usage(argv);
  } else {
    DBG() << "Read target hash of "
          << hex_encode_bigendian(options.target_hash)
          << ".\n";
  }
  unix_domain_client client(options.unix_socket_namespace);
  std::string blockbytes = slurp_input(std::cin);
  DBG() << "Read " << blockbytes.size() << " bytes of input.\n";
  if (blockbytes.size() <= 8) {
    throw std::runtime_error("Input too short for mining.");
  }
  auto stats = client.run(options.target_hash, blockbytes, *options.starting_nonce);
  print_out_nonce(stats.winning_nonce, stats.num_nonces,
                  static_cast<uint64_t>(
                    static_cast<double>(stats.num_nonces) / stats.elapsed));
  exit(0);
}

}  // namespace mining
}  // namespace crypto
}  // namespace kadena
