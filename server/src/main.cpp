#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string_view>
#include <unordered_set>

#include "../../include/protocol.hpp"

constexpr size_t kMaxPairs = 1000;

using MyUuid = std::array<char, 16>;

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
  sockaddr_in true_addr1{};
  sockaddr_in addr2{};
  uint32_t timestamp1{};
  uint32_t timestamp2{};
  bool has_server{};

  LinkItem(const MyUuid &uuid) : link_uuid(uuid) {
    AddrClear1();
    AddrClear2();
  }

  void AddrClear1() {
    addr1.sin_family = AF_INET;
    addr1.sin_port = 0;
    addr1.sin_addr.s_addr = INADDR_NONE;
    true_addr1.sin_family = AF_INET;
    true_addr1.sin_port = 0;
    true_addr1.sin_addr.s_addr = INADDR_NONE;
  }
  void AddrClear2() {
    addr2.sin_family = AF_INET;
    addr2.sin_port = 0;
    addr2.sin_addr.s_addr = INADDR_NONE;
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

bool operator==(const sockaddr_in &lhv, const sockaddr_in &rhv) {
  return lhv.sin_family == rhv.sin_family &&
         lhv.sin_addr.s_addr == rhv.sin_addr.s_addr &&
         lhv.sin_port == rhv.sin_port;
}

std::unordered_set<LinkItem, LinkItem::hash, LinkItem::equal> m_pairs;

struct ParsedArgs {
  sockaddr_in bind_addr{.sin_family = AF_INET,
                        .sin_addr = {.s_addr = INADDR_ANY}};
  bool daemonize = false;
};

ParsedArgs ParseArgs(int argc, char *argv[]) {
  ParsedArgs res{};

  option long_options[] = {{"server", required_argument, 0, 's'},
                           {"port", required_argument, 0, 'p'},
                           {"help", no_argument, 0, 'h'},
                           {0, 0, 0, 0}};

  int param;
  while ((param = getopt_long(argc, argv, "s:p:hd", long_options, nullptr)) !=
         -1) {
    switch (param) {
      case 'p':
        res.bind_addr.sin_port = htons(std::stoi(optarg));
        break;
      case 's':
        inet_pton(AF_INET, optarg, &res.bind_addr.sin_addr);
        break;
      case 'h':
        std::cout << "Options:\n"
                     " -h, --help              this help\n"
                     " -s, --server [value]    listen ip\n"
                     " -p, --port [value]      listen port\n";
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
  chdir("/");

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
  ftruncate(pid_fd, 0);
  /* Get current PID */
  auto numstr = std::to_string(getpid());
  /* Write PID to lockfile */
  write(pid_fd, numstr.data(), numstr.length());
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
      std::cout << "Invalid packet size(" << msg_size
                << ") for message kRequest";
      return;
    }
    const MessageRequest *msg = (MessageRequest *)hdr;

    std::cout << "REQUEST received" << std::endl;

    MyUuid uuid = std::to_array((char(&)[16])msg->link_uuid);
    auto it = m_pairs.find(uuid);
    if (it == m_pairs.end()) {
      if (m_pairs.size() >= kMaxPairs) {
        // TODO clean m_pairs by lru
        std::cout << "Too many pairs " << m_pairs.size();
        SendResponseError(sockfd, uuid, 1);
        return;
      }

      it = m_pairs.emplace(LinkItem{uuid}).first;
    }
    auto &pair = const_cast<LinkItem &>(*it);

    if (msg->client_type == ClientType::kClient2) {
      if (msg->timestamp < it->timestamp2) return;

      // check if already filled and old
      if (pair.addr2.sin_addr.s_addr != INADDR_NONE &&
          msg->timestamp > it->timestamp2) {
        pair.AddrClear1();
        pair.AddrClear2();
      }

      std::memcpy(&pair.addr2, &recv_addr, sizeof(recv_addr));
      pair.timestamp2 = msg->timestamp;
    } else {
      if (msg->timestamp < it->timestamp1) return;

      // check if already filled and old
      if ((pair.true_addr1.sin_addr.s_addr != INADDR_NONE ||
           pair.addr1.sin_addr.s_addr != INADDR_NONE) &&
          msg->timestamp > it->timestamp1) {
        pair.AddrClear1();
        pair.AddrClear2();
      }

      if (msg->client_type == kServer1_NoResp) {
        std::memcpy(&pair.true_addr1, &recv_addr, sizeof(recv_addr));
      } else {
        std::memcpy(&pair.addr1, &recv_addr, sizeof(recv_addr));
      }
      pair.has_server = (msg->client_type == kServer1_Resp ||
                         msg->client_type == kServer1_NoResp);
      pair.timestamp1 = msg->timestamp;
    }

    // check if all ready to answer
    if (it->has_server) {
      if (it->addr1.sin_addr.s_addr != INADDR_NONE &&
          it->addr2.sin_addr.s_addr != INADDR_NONE &&
          it->true_addr1.sin_addr.s_addr != INADDR_NONE) {
        SendResponse(sockfd, it->addr2, uuid, it->timestamp1, it->true_addr1);
        SendResponse(sockfd, it->addr1, uuid, it->timestamp2, it->addr2);
      }
    } else {
      if (it->addr1.sin_addr.s_addr != INADDR_NONE &&
          it->addr2.sin_addr.s_addr != INADDR_NONE) {
        SendResponse(sockfd, it->addr2, uuid, it->timestamp1, it->addr1);
        SendResponse(sockfd, it->addr1, uuid, it->timestamp2, it->addr2);
      }
    }
  } else if (hdr->type == MessageType::kConfirmation) {
    if (msg_size != sizeof(MessageConfirmation)) {
      std::cout << "Invalid packet size(" << msg_size
                << ") for message kConfirmation";
      return;
    }
    const MessageConfirmation *msg = (MessageConfirmation *)hdr;

    std::cout << "CONFIRMATION received" << std::endl;

    // MyUuid uuid = std::to_array((char(&)[16])msg->link_uuid);
    // auto it = m_pairs.find(uuid);
    // if (it != m_pairs.end()) {
    //    if (recv_addr == it->addr1 && msg->request_ts == it->timestamp2) {
    //    }
    //    if (recv_addr == it->addr2 && msg->request_ts == it->timestamp1) {
    //    }
    // }
  } else {
    std::cout << "Invalid packet(" << msg_size << ") for message " << hdr->type;
  }
}

int main(int argc, char *argv[]) {
  std::cout << "udphp server v0.0.1" << std::endl;

  auto settings = ParseArgs(argc, argv);

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

  char addrstr[128] = {};
  inet_ntop(settings.bind_addr.sin_family, &settings.bind_addr.sin_addr,
            addrstr, sizeof(addrstr));
  std::cout << "Listen on " << addrstr << ":"
            << ntohs(settings.bind_addr.sin_port) << std::endl;

  char buf[64 * 1024];

  sockaddr_in recv_addr{};
  socklen_t recv_addr_len = sizeof(recv_addr);

  while (1) {
    pollfd pfd = {.fd = sockfd, .events = POLLIN};
    auto res = poll(&pfd, 1, 15000);
    if (res > 0) {
      if (pfd.events & POLLIN) {
        ssize_t received = recvfrom(sockfd, buf, sizeof(buf), 0,
                                    (sockaddr *)&recv_addr, &recv_addr_len);
        if (received <= 0) {
          perror("received <= 0");
          exit(EXIT_FAILURE);
        }

        inet_ntop(recv_addr.sin_family, &recv_addr.sin_addr, addrstr, 100);

        if (received < ssize_t(sizeof(MessageHdr))) {
          std::cout << addrstr << ":" << ntohs(recv_addr.sin_port)
                    << "\tUnknown packet with size " << received;
          continue;
        }

        std::cout << "RECEIVED: " << addrstr << ":" << ntohs(recv_addr.sin_port)
                  << " " << string_to_hex(std::string(buf, received))
                  << std::endl;

        ProcessMessage(sockfd, recv_addr, (MessageHdr *)buf, received);
      }
    } else if (res == 0) {
      // std::cout << "15 seconds..." << std::endl;
    } else {
      perror("poll failed");
      exit(EXIT_FAILURE);
    }
  }

  close(sockfd);

  std::cout << "Check finished" << std::endl;

  return EXIT_SUCCESS;
}