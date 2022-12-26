#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string_view>
#include <unordered_set>

#include "protocol.hpp"

constexpr size_t kMaxPairs = 1000;

using MyUuid = std::array<char, 16>;

inline std::ostream &operator<<(std::ostream &os, const MyUuid &uuid) {
  char uuid_str[50] = {};
  uuid_unparse((uint8_t *)uuid.data(), uuid_str);
  return os << uuid_str;
}

inline std::ostream &operator<<(std::ostream &os, const sockaddr_in &addr) {
  char addrstr[100] = {};
  inet_ntop(addr.sin_family, &addr.sin_addr, addrstr, sizeof(addrstr));
  return os << addrstr << ':' << ntohs(addr.sin_port);
}

inline std::ostream &operator<<(std::ostream &os, const MessageType type) {
  if (type == kRequest)
    return os << "kRequest";
  else if (type == kResponse)
    return os << "kResponse";
  else if (type == kConfirmation)
    return os << "kConfirmation";
  return os << "UNKNOWN";
}

std::string string_to_hex(const std::string &input) {
  static const char hex_digits[] = "0123456789ABCDEF";

  std::string output;
  output.reserve(input.length() * 2);
  for (unsigned char c : input) {
    output.push_back(hex_digits[c >> 4]);
    output.push_back(hex_digits[c & 15]);
  }
  return output;
}

struct LinkItem {
  MyUuid link_uuid{};
  sockaddr_in addr1{};
  sockaddr_in addr1_second{};
  sockaddr_in addr2{};
  sockaddr_in addr2_second{};
  uint32_t timestamp1{};
  uint32_t timestamp2{};
  bool has_second1{};
  bool has_second2{};
  std::chrono::system_clock::time_point last_used{};

  LinkItem(const MyUuid &uuid) : link_uuid(uuid) {
    AddrClear1();
    AddrClear2();
  }

  void AddrClear1() {
    addr1 = sockaddr_in{.sin_family = AF_INET,
                        .sin_port = 0,
                        .sin_addr = {.s_addr = INADDR_NONE}};
    addr1_second = addr1;
    has_second1 = false;
  }
  void AddrClear2() {
    addr2 = sockaddr_in{.sin_family = AF_INET,
                        .sin_port = 0,
                        .sin_addr = {.s_addr = INADDR_NONE}};
    addr2_second = addr2;
    has_second2 = false;
  }

  struct equal {
    using is_transparent = void;

    bool operator()(const LinkItem &lhv, const LinkItem &rhv) const {
      return lhv.link_uuid == rhv.link_uuid;
    }
    // bool operator()(const LinkItem &lhv, const MyUuid &rhv) const {
    //   return lhv.link_uuid == rhv;
    // }
    bool operator()(const MyUuid &lhv, const LinkItem &rhv) const {
      return lhv == rhv.link_uuid;
    }
  };

  struct hash {
    using is_transparent = void;

    std::size_t operator()(const LinkItem &val) const {
      return std::hash<std::string_view>{}(
          std::string_view(val.link_uuid.data(), sizeof(val.link_uuid)));
    }
    std::size_t operator()(const MyUuid &val) const {
      return std::hash<std::string_view>{}(
          std::string_view(val.data(), sizeof(val)));
    }
  };
};

template <typename... Args>
void Log(Args &&...args) {
  char timebuf[40];

  std::time_t time = std::time(nullptr);
  std::strftime(std::data(timebuf), std::size(timebuf), "%Y-%m-%d %H:%M:%S",
                std::gmtime(&time));

  std::cout << timebuf << '\t';
  ((std::cout << std::forward<Args>(args)), ...);
  std::cout << std::endl;
}

bool operator==(const sockaddr_in &lhv, const sockaddr_in &rhv) {
  return lhv.sin_family == rhv.sin_family &&
         lhv.sin_addr.s_addr == rhv.sin_addr.s_addr &&
         lhv.sin_port == rhv.sin_port;
}

std::string LogPacket(const char *buf, size_t buf_size) {
  if (buf_size >= ssize_t(sizeof(MessageHdr))) {
    MessageHdr *hdr = (MessageHdr *)buf;
    if (hdr->type == kRequest || hdr->type == kResponse ||
        hdr->type == kConfirmation) {
      std::ostringstream ostr;

      MyUuid uuid = std::to_array((char(&)[16])hdr->link_uuid);
      ostr << uuid << '\t' << MessageType{hdr->type} << ", "
           << string_to_hex(std::string(buf + sizeof(MessageHdr),
                                        buf_size - sizeof(MessageHdr)));
      return ostr.str();
    }
  }

  return string_to_hex(std::string(buf, buf_size));
}

std::unordered_set<LinkItem, LinkItem::hash, LinkItem::equal> m_pairs;

struct ParsedArgs {
  sockaddr_in bind_addr{.sin_family = AF_INET,
                        .sin_addr = {.s_addr = INADDR_ANY}};
  bool daemonize = false;
};

ParsedArgs ParseArgs(int argc, char *argv[]) {
  ParsedArgs res{};

  option long_options[] = {{"ip", required_argument, 0, 'i'},
                           {"port", required_argument, 0, 'p'},
                           {"daemon", no_argument, 0, 'd'},
                           {"help", no_argument, 0, 'h'},
                           {0, 0, 0, 0}};

  int param;
  while ((param = getopt_long(argc, argv, "i:p:hd", long_options, nullptr)) !=
         -1) {
    switch (param) {
      case 'p':
        res.bind_addr.sin_port = htons(std::stoi(optarg));
        break;
      case 'i':
        inet_pton(AF_INET, optarg, &res.bind_addr.sin_addr);
        break;
      case 'h':
        std::cout << "Options:\n"
                     " -h, --help              this help\n"
                     " -i, --ip [value]        listen ip\n"
                     " -p, --port [value]      listen port\n"
                     " -d, --daemon            daemon mode\n";
        exit(EXIT_SUCCESS);
        break;
      case 'd':
        res.daemonize = true;
        break;
      default:
        std::cout << "Unknown parameter " << param << std::endl;
        throw std::runtime_error("Unknown parameter");
    }
  }

  if (optind < argc) {
    std::cout << "Non-option argv parameters" << std::endl;
    throw std::runtime_error("Non-option argv parameters");
  }

  if (res.bind_addr.sin_port == 0) {
    std::cout << "No valid port selected" << std::endl;
    throw std::runtime_error("No valid port selected");
  }

  return res;
}

void Daemonize() {
  // An error occurred
  auto pid = fork();
  if (pid < 0) {
    perror("fork failed");
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  // The child process becomes session leader
  if (setsid() < 0) {
    perror("fork failed");
    exit(EXIT_FAILURE);
  }

  // Ignore signal sent from child to parent process
  signal(SIGCHLD, SIG_IGN);

  // Fork off for the second time
  pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  // Set new file permissions
  umask(0);

  // Change current dir
  if (chdir("/") < 0) {
    perror("chdir failed");
  }

  // Close out the standard file descriptors
  auto logfd = open("/var/log/udphp.log", O_CREAT | O_WRONLY | O_APPEND, 0640);
  if (logfd < 0) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
  } else {
    close(STDIN_FILENO);
    dup2(logfd, STDOUT_FILENO);
    dup2(logfd, STDERR_FILENO);
  }

  auto pid_fd = open("/var/run/udphp.lock", O_RDWR | O_CREAT, 0640);
  if (pid_fd < 0) {
    perror("open failed");
    /* Can't open lockfile */
    exit(EXIT_FAILURE);
  }
  if (lockf(pid_fd, F_TLOCK, 0) < 0) {
    /* Can't lock file */
    exit(EXIT_FAILURE);
  }
  if (ftruncate(pid_fd, 0) < 0) {
    perror("ftruncate failed");
  }
  /* Get current PID */
  auto numstr = std::to_string(getpid());
  /* Write PID to lockfile */
  if (write(pid_fd, numstr.data(), numstr.length()) !=
      (ssize_t)numstr.length()) {
    perror("write failed");
  }
}

void SendResponseError(int sockfd, MyUuid uuid, int status) {}

void SendResponse(int sockfd, const sockaddr_in &addr, const MyUuid &uuid,
                  uint64_t request_ts, const sockaddr_in &answer_addr) {
  MessageResponse msg{};
  std::memcpy(msg.link_uuid, uuid.data(), sizeof(uuid));
  msg.request_ts = request_ts;
  msg.ip_addr = answer_addr.sin_addr.s_addr;
  msg.ip_port = answer_addr.sin_port;

  if (sendto(sockfd, &msg, sizeof(msg), 0, (sockaddr *)&addr, sizeof(addr)) <=
      0) {
    perror("sendto failed");
  }
}

void ProcessMessage(int sockfd, const sockaddr_in &recv_addr,
                    const MessageHdr *hdr, size_t msg_size) {
  if (hdr->type == MessageType::kRequest) {
    if (msg_size != sizeof(MessageRequest)) {
      Log(recv_addr, "\tInvalid packet size(", msg_size,
          ") for message kRequest");
      return;
    }
    const MessageRequest *msg = (MessageRequest *)hdr;
    MyUuid uuid = std::to_array((char(&)[16])msg->link_uuid);
    auto it = m_pairs.find(uuid);
    if (it == m_pairs.end()) {
      if (m_pairs.size() >= kMaxPairs) {
        // TODO clean m_pairs by lru
        Log(recv_addr, "\tToo many pairs ", m_pairs.size());
        SendResponseError(sockfd, uuid, 1);
        return;
      }

      it = m_pairs.emplace(LinkItem{uuid}).first;
      Log(recv_addr, '\t', uuid, "\tnew record");
    } else {
      Log(recv_addr, '\t', uuid, "\tdata found");
    }

    auto &pair = const_cast<LinkItem &>(*it);

    if (msg->client_type == ClientType::kClient1_Direct ||
        msg->client_type == ClientType::kClient1_Control ||
        msg->client_type == ClientType::kClient1_Second) {
      if (msg->timestamp < pair.timestamp1) {
        Log(recv_addr, '\t', uuid, "\told request(1)");
        return;
      }
      // check if already filled and old
      if ((pair.addr1.sin_addr.s_addr != INADDR_NONE ||
           pair.addr1_second.sin_addr.s_addr != INADDR_NONE) &&
          msg->timestamp > pair.timestamp1) {
        pair.AddrClear1();
        pair.AddrClear2();
      }
      std::memcpy(msg->client_type == kClient1_Second ? &pair.addr1_second
                                                      : &pair.addr1,
                  &recv_addr, sizeof(recv_addr));
      pair.has_second1 = (msg->client_type == ClientType::kClient1_Control ||
                          msg->client_type == ClientType::kClient1_Second);
      pair.timestamp1 = msg->timestamp;
    } else if (msg->client_type == ClientType::kClient2_Direct ||
               msg->client_type == ClientType::kClient2_Control ||
               msg->client_type == ClientType::kClient2_Second) {
      if (msg->timestamp < pair.timestamp2) {
        Log(recv_addr, '\t', uuid, "\told request(2)");
        return;
      }
      // check if already filled and old
      if ((pair.addr2.sin_addr.s_addr != INADDR_NONE ||
           pair.addr2_second.sin_addr.s_addr != INADDR_NONE) &&
          msg->timestamp > pair.timestamp2) {
        pair.AddrClear1();
        pair.AddrClear2();
      }

      std::memcpy(msg->client_type == kClient2_Second ? &pair.addr2_second
                                                      : &pair.addr2,
                  &recv_addr, sizeof(recv_addr));
      pair.has_second2 = (msg->client_type == ClientType::kClient2_Control ||
                          msg->client_type == ClientType::kClient2_Second);
      pair.timestamp2 = msg->timestamp;
    } else {
      Log(recv_addr, "\tUnknown client type(", int(msg->client_type),
          ") for message kRequest");
      return;
    }

    pair.last_used = std::chrono::system_clock::now();

    // check if all ready to answer
    if (pair.addr1.sin_addr.s_addr != INADDR_NONE &&
        pair.addr2.sin_addr.s_addr != INADDR_NONE &&
        (!pair.has_second1 ||
         pair.addr1_second.sin_addr.s_addr != INADDR_NONE) &&
        (!pair.has_second2 ||
         pair.addr2_second.sin_addr.s_addr != INADDR_NONE)) {
      SendResponse(sockfd, pair.addr2, uuid, pair.timestamp1,
                   pair.has_second1 ? pair.addr1_second : pair.addr1);
      SendResponse(sockfd, pair.addr1, uuid, pair.timestamp2,
                   pair.has_second2 ? pair.addr2_second : pair.addr2);
    }
  } else if (hdr->type == MessageType::kConfirmation) {
    if (msg_size != sizeof(MessageConfirmation)) {
      Log(recv_addr, "\tInvalid packet size(", msg_size,
          ") for message kConfirmation");
      return;
    }
    const MessageConfirmation *msg = (MessageConfirmation *)hdr;

    MyUuid uuid = std::to_array((char(&)[16])msg->link_uuid);
    auto it = m_pairs.find(uuid);
    if (it != m_pairs.end()) {
      Log(recv_addr, '\t', uuid, "\trecord found, last_used updated");
      auto &pair = const_cast<LinkItem &>(*it);
      pair.last_used = std::chrono::system_clock::now();
    }
  } else {
    Log(recv_addr, "\tInvalid packet(", msg_size, ") for message ", hdr->type);
  }
}

int main(int argc, char *argv[]) {
  std::cout << "udphp server v0.0.1" << std::endl;

  const auto settings = ParseArgs(argc, argv);

  if (settings.daemonize) {
    Daemonize();
  }

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd == -1) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  int enable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  // int flags = fcntl(sockfd, F_GETFL, 0);
  // if (flags < 0) {
  //   perror("fcntl failed");
  //   exit(EXIT_FAILURE);
  // }
  // std::cout << "flag: " << flags << std::endl;
  // if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
  //   perror("fcntl(2) failed");
  //   exit(EXIT_FAILURE);
  // }

  if (bind(sockfd, (sockaddr *)&settings.bind_addr,
           sizeof(settings.bind_addr)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  Log("\t\tListen on ", settings.bind_addr);

  char buf[1024];

  while (1) {
    pollfd pfd = {.fd = sockfd, .events = POLLIN};
    auto res = poll(&pfd, 1, 30000);
    if (res > 0) {
      if (pfd.events & POLLIN) {
        sockaddr_in recv_addr{};
        socklen_t recv_addr_len = sizeof(recv_addr);

        ssize_t received = recvfrom(sockfd, buf, sizeof(buf), 0,
                                    (sockaddr *)&recv_addr, &recv_addr_len);
        if (received <= 0) {
          perror("received <= 0");
          exit(EXIT_FAILURE);
        }

        if (received < ssize_t(sizeof(MessageHdr))) {
          Log(recv_addr, "\tUnknown packet with size ", received);
          continue;
        }

        Log(recv_addr, '\t', LogPacket(buf, received), " RECEVED");

        ProcessMessage(sockfd, recv_addr, (MessageHdr *)buf, received);
      }
    } else if (res == 0) {
      const auto now = std::chrono::system_clock::now();

      auto it = m_pairs.begin();
      while (it != m_pairs.end()) {
        if (it->last_used + std::chrono::seconds{60} < now) {
          Log('\t', it->link_uuid, " record removed from base");
          it = m_pairs.erase(it);
        } else
          ++it;
      }
    } else {
      perror("poll failed");
      exit(EXIT_FAILURE);
    }
  }

  close(sockfd);

  Log("\t\tService stopped");

  return EXIT_SUCCESS;
}