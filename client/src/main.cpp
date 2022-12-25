#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/udp.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string_view>
#include <unordered_set>

#include "protocol.hpp"

using MyUuid = std::array<char, 16>;

inline std::ostream &operator<<(std::ostream &os, const sockaddr_in &addr) {
  char addrstr[100] = {};
  inet_ntop(addr.sin_family, &addr.sin_addr, addrstr, sizeof(addrstr));
  return os << addrstr << ':' << ntohs(addr.sin_port);
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

bool operator==(const sockaddr_in &lhv, const sockaddr_in &rhv) {
  return lhv.sin_family == rhv.sin_family &&
         lhv.sin_addr.s_addr == rhv.sin_addr.s_addr &&
         lhv.sin_port == rhv.sin_port;
}
bool operator!=(const sockaddr_in &lhv, const sockaddr_in &rhv) {
  return !(lhv == rhv);
}

void SendRaw(const sockaddr_in &bind_addr, const sockaddr_in &connect_addr,
             const void *msg, size_t msg_size) {
  int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (rawfd == -1) {
    perror("socket(2) failed");
    exit(EXIT_FAILURE);
  }

  if (bind(rawfd, (sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  char buf[2048] = {};
  //  sizeof(udphdr) + 4096
  udphdr *hdr = (udphdr *)buf;
  std::memcpy(hdr + 1, msg, msg_size);

  memset(hdr, 0, sizeof(udphdr));
  hdr->source = bind_addr.sin_port;
  hdr->dest = connect_addr.sin_port;
  hdr->len = htons(sizeof(udphdr) + msg_size);

  if (sendto(rawfd, hdr, sizeof(udphdr) + msg_size, 0,
             (sockaddr *)&connect_addr, sizeof(connect_addr)) <= 0) {
    perror("sendto(4) failed");
    exit(EXIT_FAILURE);
  }

  close(rawfd);
}

struct ParsedArgs {
  sockaddr_in bind_addr{.sin_family = AF_INET,
                        .sin_addr = {.s_addr = INADDR_ANY}};
  sockaddr_in connect_addr{.sin_family = AF_INET,
                           .sin_addr = {.s_addr = INADDR_NONE}};
  ClientType type = kClient1_Direct;
  MyUuid uuid{};
};

ParsedArgs ParseArgs(int argc, char *argv[]) {
  ParsedArgs res{};

  option long_options[] = {{"ip", required_argument, 0, 'i'},
                           {"port", required_argument, 0, 'p'},
                           {"client1", no_argument, 0, '1'},
                           {"client2", no_argument, 0, '2'},
                           {0, 0, 0, 0}};

  int param;
  while ((param = getopt_long(argc, argv, "i:p:h12", long_options, nullptr)) !=
         -1) {
    switch (param) {
      case 'p':
        res.bind_addr.sin_port = htons(std::stoi(optarg));
        break;
      case 'i':
        inet_pton(AF_INET, optarg, &res.bind_addr.sin_addr);
        break;
      case '1':
        res.type = kClient1_Direct;
        break;
      case '2':
        res.type = kClient2_Direct;
        break;
      case 'h':
        std::cout
            << "Options:\n"
               " -h,   --help              this help\n"
               " -s,   --server [value]    ip mapping, second request\n"
               " -p,   --port [value]      port mapping, second request\n"
               " -1,   --client1           send request as client#1 (default)\n"
               " -2,   --client2           send request as client#2\n"
               " [uuid] [address:port]\n";
        exit(EXIT_SUCCESS);
        break;
      default:
        std::cout << "Unknown parameter " << param << std::endl;
        throw std::runtime_error("Unknown parameter");
    }
  }

  if (optind + 2 == argc) {
    uuid_t myuuid;
    uuid_parse(argv[optind], myuuid);
    res.uuid = std::to_array((char(&)[16])myuuid);

    std::string address = argv[optind + 1];
    auto pos = address.find_last_of(':');
    if (pos != std::string::npos) {
      addrinfo hints{};
      hints.ai_family = AF_INET;
      hints.ai_protocol = IPPROTO_UDP;
      addrinfo *addr_info = nullptr;

      if (getaddrinfo(address.substr(0, pos).c_str(),
                      address.substr(pos + 1).c_str(), &hints,
                      &addr_info) != 0 ||
          addr_info == nullptr) {
        perror("getaddrinfo failed");
        exit(EXIT_FAILURE);
      }
      freeaddrinfo(addr_info);

      std::memcpy(&res.connect_addr, addr_info->ai_addr,
                  sizeof(res.connect_addr));
    }
  }

  if (res.connect_addr.sin_addr.s_addr == INADDR_NONE ||
      res.connect_addr.sin_port == 0) {
    std::cout << "Missing required [uuid] [address:port]" << std::endl;
    throw std::runtime_error("Missing required [uuid] [address:port]");
  }

  if (res.bind_addr.sin_port != 0) {
    res.type =
        (res.type == kClient2_Direct ? kClient2_Control : kClient1_Control);
  }

  return res;
}

int main(int argc, char *argv[]) {
  std::cout << "udphp client v0.0.1" << std::endl;

  const auto settings = ParseArgs(argc, argv);

  size_t unix_timestamp = std::chrono::seconds(std::time(nullptr)).count();

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd == -1) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  int enable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  MessageRequest msg_req{};
  memcpy(msg_req.link_uuid, settings.uuid.data(), settings.uuid.size());
  msg_req.client_type = settings.type;
  msg_req.timestamp = unix_timestamp;

  if (sendto(sockfd, &msg_req, sizeof(msg_req), 0,
             (sockaddr *)&settings.connect_addr,
             sizeof(settings.connect_addr)) <= 0) {
    perror("sendto failed");
    exit(EXIT_FAILURE);
  }
  if (settings.type == kClient1_Control || settings.type == kClient2_Control) {
    auto msg_req2{msg_req};
    msg_req2.client_type =
        (settings.type == kClient2_Control ? kClient2_Second : kClient1_Second);
    SendRaw(settings.bind_addr, settings.connect_addr, &msg_req2,
            sizeof(msg_req2));
  }

  struct sockaddr_in bind_addr;
  socklen_t len = sizeof(bind_addr);
  if (getsockname(sockfd, (struct sockaddr *)&bind_addr, &len) < 0) {
    perror("getsockname failed");
    exit(EXIT_FAILURE);
  }
  std::cout << "MYADDRESS: " << bind_addr << std::endl;

  char buf[1024];

  sockaddr_in recv_addr{};
  socklen_t recv_addr_len = sizeof(recv_addr);
  int tries = 0;

  while (1) {
    pollfd pfd = {.fd = sockfd, .events = POLLIN, .revents = 255};
    auto res = poll(&pfd, 1, 10000);
    if (res > 0) {
      if (pfd.events & POLLIN) {
        ssize_t received = recvfrom(sockfd, buf, sizeof(buf), 0,
                                    (sockaddr *)&recv_addr, &recv_addr_len);
        if (received <= 0) {
          perror("received <= 0");
          exit(EXIT_FAILURE);
        }

        std::cout << "RECEIVED " << recv_addr << " "
                  << string_to_hex(std::string(buf, received)) << std::endl;

        if (recv_addr != settings.connect_addr) {
          std::cout << recv_addr << "\tPacket from invalid address, skipping"
                    << std::endl;
          continue;
        }

        if (received != sizeof(MessageResponse)) {
          std::cout << recv_addr << "\tUnknown packet with size " << received;
          exit(EXIT_FAILURE);
        }

        MessageResponse *msg = (MessageResponse *)buf;
        if (msg->type != MessageType::kResponse ||
            std::memcmp(msg->link_uuid, msg_req.link_uuid,
                        sizeof(msg_req.link_uuid)) != 0) {
          std::cout << recv_addr << "\tInvlaid MessageResponse received "
                    << received;
          exit(EXIT_FAILURE);
        }

        sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = msg->ip_addr;
        client_addr.sin_port = msg->ip_port;

        // sendto to result
        if (settings.type == kClient1_Control ||
            settings.type == kClient2_Control) {
          SendRaw(settings.bind_addr, client_addr, nullptr, 0);
          std::cout << "BIND: " << settings.bind_addr << std::endl;
        } else {
          if (sendto(sockfd, nullptr, 0, 0, (sockaddr *)&client_addr,
                     sizeof(client_addr)) < 0) {
            perror("sendto(2) failed");
            exit(EXIT_FAILURE);
          }
          std::cout << "BIND: " << bind_addr << std::endl;
        }

        // send confirmation
        MessageConfirmation msg_conf{};
        memcpy(msg_conf.link_uuid, settings.uuid.data(), settings.uuid.size());
        msg_conf.request_ts = msg->request_ts;

        sendto(sockfd, &msg_conf, sizeof(msg_conf), 0,
               (sockaddr *)&settings.connect_addr,
               sizeof(settings.connect_addr));

        std::cout << "CLIENT: " << client_addr << std::endl;
        break;
      }
    } else if (res == 0) {
      std::cout << "try " << ++tries << ", repeat..." << std::endl;

      if (sendto(sockfd, &msg_req, sizeof(msg_req), 0,
                 (sockaddr *)&settings.connect_addr,
                 sizeof(settings.connect_addr)) <= 0) {
        perror("sendto(3) failed");
        exit(EXIT_FAILURE);
      }
      if (settings.type == kClient1_Control ||
          settings.type == kClient2_Control) {
        auto msg_req2{msg_req};
        msg_req2.client_type =
            (settings.type == kClient2_Control ? kClient2_Second
                                               : kClient1_Second);
        SendRaw(settings.bind_addr, settings.connect_addr, &msg_req2,
                sizeof(msg_req2));
      }
    } else {
      perror("poll failed");
      exit(EXIT_FAILURE);
    }
  }

  close(sockfd);

  // std::cout << "Check finished" << std::endl;

  return EXIT_SUCCESS;
}