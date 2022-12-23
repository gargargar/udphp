#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string_view>
#include <tuple>
#include <unordered_set>

#include "../../include/protocol.hpp"

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
}

std::tuple<sockaddr_in, MyUuid, ClientType, sockaddr_in> ParseArgs(
    int argc, char *argv[]) {
  sockaddr_in res_addr{};
  sockaddr_in raw_addr{};
  MyUuid res_uuid{};
  ClientType res_type = kClient1;
  res_addr.sin_family = AF_INET;
  res_addr.sin_addr.s_addr = INADDR_NONE;
  res_addr.sin_port = 0;
  raw_addr.sin_family = AF_INET;
  raw_addr.sin_addr.s_addr = INADDR_ANY;
  raw_addr.sin_port = 0;

  option long_options[] = {{"server", required_argument, 0, 's'},
                           {"port", required_argument, 0, 'p'},
                           {"client1", no_argument, 0, '1'},
                           {"client2", no_argument, 0, '2'},
                           {0, 0, 0, 0}};

  int param;
  while ((param = getopt_long(argc, argv, "s:p:h12", long_options, nullptr)) !=
         -1) {
    switch (param) {
      case 'p':
        raw_addr.sin_port = htons(std::stoi(optarg));
        res_type = kServer1_Resp;
        break;
      case 's':
        inet_pton(AF_INET, optarg, &raw_addr.sin_addr);
        break;
      case '1':
        res_type = kClient1;
        break;
      case '2':
        res_type = kClient2;
        break;
      case 'h':
        std::cout
            << "Options:\n"
               " -s,   --server [value] ip mapping, server mode\n"
               " -p,   --port [value]   port mapping, server mode\n"
               " -1,   --client1        send request as client#1 (default)\n"
               " -2,   --client2        send request as client#2\n"
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
    res_uuid = std::to_array((char(&)[16])myuuid);

    std::string address = argv[optind + 1];
    auto pos = address.find_last_of(':');
    if (pos != std::string::npos) {
      inet_pton(AF_INET, address.substr(0, pos).c_str(), &res_addr.sin_addr);
      res_addr.sin_port = htons(std::stoi(address.substr(pos + 1)));
    }
  }

  if (res_addr.sin_addr.s_addr == INADDR_NONE || res_addr.sin_port == 0) {
    std::cout << "Missing required [uuid] [address:port]" << std::endl;
    throw std::runtime_error("Missing required [uuid] [address:port]");
  }

  return {std::move(res_addr), res_uuid, res_type, raw_addr};
}

int main(int argc, char *argv[]) {
  std::cout << "udphp client v0.0.1" << std::endl;

  auto [connect_addr, uuid, client_type, raw_addr] = ParseArgs(argc, argv);

  size_t unix_timestamp = std::chrono::seconds(std::time(nullptr)).count();
  std::cout << "UNIXTIME: " << unix_timestamp << std::endl;

  char addrstr[128] = {};
  inet_ntop(connect_addr.sin_family, &connect_addr.sin_addr, addrstr,
            sizeof(addrstr));

  std::cout << "PARAM: " << addrstr << ":" << ntohs(connect_addr.sin_port)
            << ", " << int(client_type) << std::endl;

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd == -1) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  int enable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  MessageRequest msg_req{};
  memcpy(msg_req.link_uuid, uuid.data(), uuid.size());
  msg_req.client_type = client_type;
  msg_req.timestamp = unix_timestamp;

  if (sendto(sockfd, &msg_req, sizeof(msg_req), 0, (sockaddr *)&connect_addr,
             sizeof(connect_addr)) <= 0) {
    perror("sendto failed");
    exit(EXIT_FAILURE);
  }
  if (client_type == kServer1_Resp) {
    auto msg_req2{msg_req};
    msg_req2.client_type = kServer1_NoResp;
    SendRaw(raw_addr, connect_addr, &msg_req2, sizeof(msg_req2));
  }

  struct sockaddr_in bind_addr;
  socklen_t len = sizeof(bind_addr);
  if (getsockname(sockfd, (struct sockaddr *)&bind_addr, &len) < 0) {
    perror("getsockname failed");
    exit(EXIT_FAILURE);
  }
  inet_ntop(bind_addr.sin_family, &bind_addr.sin_addr, addrstr, 100);
  std::cout << "MYADDRESS: " << addrstr << ":" << ntohs(bind_addr.sin_port)
            << std::endl;

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

        inet_ntop(recv_addr.sin_family, &recv_addr.sin_addr, addrstr, 100);

        std::cout << "RECEIVED " << addrstr << ":" << ntohs(recv_addr.sin_port)
                  << " " << string_to_hex(std::string(buf, received))
                  << std::endl;

        if (recv_addr != connect_addr) {
          std::cout << "packet from invalid address, skipping" << std::endl;
          continue;
        }

        if (received != sizeof(MessageResponse)) {
          std::cout << addrstr << ":" << ntohs(recv_addr.sin_port)
                    << "\tUnknown packet with size " << received;
          exit(EXIT_FAILURE);
        }

        MessageResponse *msg = (MessageResponse *)buf;
        if (msg->type != MessageType::kResponse ||
            std::memcmp(msg->link_uuid, msg_req.link_uuid,
                        sizeof(msg_req.link_uuid)) != 0) {
          std::cout << addrstr << ":" << ntohs(recv_addr.sin_port)
                    << "\tInvlaid MessageResponse received " << received;
          exit(EXIT_FAILURE);
        }

        sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = msg->ip_addr;
        client_addr.sin_port = msg->ip_port;

        inet_ntop(client_addr.sin_family, &client_addr.sin_addr, addrstr,
                  sizeof(addrstr));
        std::cout << "CLIENT: " << addrstr << ":" << ntohs(client_addr.sin_port)
                  << std::endl;

        // sendto to result
        if (client_type == kServer1_Resp) {
          SendRaw(raw_addr, client_addr, nullptr, 0);

          inet_ntop(raw_addr.sin_family, &raw_addr.sin_addr, addrstr,
                    sizeof(addrstr));
          std::cout << "BIND: " << addrstr << ":" << ntohs(raw_addr.sin_port)
                    << std::endl;

        } else {
          if (sendto(sockfd, nullptr, 0, 0, (sockaddr *)&client_addr,
                     sizeof(client_addr)) < 0) {
            perror("sendto(2) failed");
            exit(EXIT_FAILURE);
          }

          inet_ntop(bind_addr.sin_family, &bind_addr.sin_addr, addrstr,
                    sizeof(addrstr));
          std::cout << "BIND: " << addrstr << ":" << ntohs(bind_addr.sin_port)
                    << std::endl;
        }

        // send confirmation
        MessageConfirmation msg_conf{};
        memcpy(msg_conf.link_uuid, uuid.data(), uuid.size());
        msg_conf.request_ts = msg->request_ts;

        sendto(sockfd, &msg_conf, sizeof(msg_conf), 0,
               (sockaddr *)&connect_addr, sizeof(connect_addr));

        break;
      }
    } else if (res == 0) {
      std::cout << "try " << ++tries << ", repeat..." << std::endl;

      if (sendto(sockfd, &msg_req, sizeof(msg_req), 0,
                 (sockaddr *)&connect_addr, sizeof(connect_addr)) <= 0) {
        perror("sendto(3) failed");
        exit(EXIT_FAILURE);
      }
      if (client_type == kServer1_Resp) {
        auto msg_req2{msg_req};
        msg_req2.client_type = kServer1_NoResp;
        SendRaw(raw_addr, connect_addr, &msg_req2, sizeof(msg_req2));
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