/*
 * Copyright (C) 2020 Roman Ondráček <xondra58@stud.fit.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <iostream>
#include <arpa/inet.h>
#include <chrono>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <vector>
#include <iomanip>
#include <getopt.h>
#include <sstream>

/**
 * Resolves PTR record
 * @param addressFamily Address family (IPv4, IPv6)
 * @param address Address
 * @return Hostname or address
 */
std::string resolvePtr(int addressFamily, const void* address) {
    char hostname[NI_MAXHOST];
    char addressStr[INET6_ADDRSTRLEN];
    inet_ntop(addressFamily, address, addressStr, INET6_ADDRSTRLEN);
    struct addrinfo hints = {}, *result;
    hints.ai_family = addressFamily;
    int retVal = getaddrinfo(addressStr, nullptr, &hints, &result);
    if (retVal == 0) {
        size_t resultLen = result->ai_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        retVal = getnameinfo(result->ai_addr, resultLen, hostname, sizeof(hostname), nullptr, 0, NI_IDN | NI_NAMEREQD);
        freeaddrinfo(result);
    }
    if (retVal != 0) {
        if (addressFamily == AF_INET) {
            return std::string(addressStr);
        } else {
            return std::string(addressStr).insert(0, "[").append("]");
        }
    }
    return std::string(hostname);
}

/**
 * Lists available interfaces
 */
void listInterfaces() {
    char errorBuffer[PCAP_ERRBUF_SIZE] = "";
    pcap_if_t *interfaces = nullptr;
    if (pcap_findalldevs(&interfaces, errorBuffer) == PCAP_ERROR) {
        std::cerr << "Error in pcap_findalldevs: " << errorBuffer << std::endl;
        throw std::exception();
    }
    std::cout << "Available interfaces:" << std::endl;
    for (pcap_if_t* interface = interfaces; interface; interface = interface->next) {
        if ((interface->flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE) == PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE) {
            continue;
        }
        std::cout << "\t" << interface->name << std::endl;
    }
    pcap_freealldevs(interfaces);
}

/**
 * Print the help
 * @param output Output
 * @param name Program name
 */
void printHelp(std::ostream &output, const std::string &name) {
    output << "Usage: " << name << " [options]" << std::endl;
    output << "Options:" << std::endl;
    output << "\t-h, --help\t\t\tPrint this message" << std::endl;
    output << "\t-I, --list-interfaces\t\tPrint available interfaces" << std::endl;
    output << "\t-i, --interface interface\tListen on interface" << std::endl;
    output << "\t-p, --port port\t\t\tListen on the port" << std::endl;
    output << "\t-t, --tcp\t\t\tDisplay only TCP traffic" << std::endl;
    output << "\t-u, --udp\t\t\tDisplay only UDP traffic" << std::endl;
    output << "\t-n, --count n\t\t\tExit after receiving n packets (default: n=1)" << std::endl;
}

/**
 * Prints time
 * @param time Time
 */
void printTime(timeval time) {
    std::tm tm = *std::localtime(&time.tv_sec);
    std::ostringstream microseconds;
    microseconds.fill('0');
    microseconds << std::setw(6) << std::to_string(time.tv_usec);
    std::cout << std::put_time(&tm, "%T") << "." << microseconds.str() << " ";
}

/**
 * Prints packet
 * @param packet Captured packtet
 * @param size Packet size
 */
void printPacket(const u_char *packet, unsigned int size) {
    uint8_t bytesPerLine = 16;
    unsigned long offset = 0;
    std::cout << std::endl;
    for (unsigned int bytesRead = 0; bytesRead < size; bytesRead += bytesPerLine) {
        unsigned int bytesLeft = size - bytesRead;
        if (bytesLeft > bytesPerLine) {
            bytesLeft = bytesPerLine;
        }
        std::cout << "0x" << std::setfill('0') <<  std::setw(4) << std::hex << offset;
        for (uint8_t i = 0; i < bytesPerLine; ++i) {
            if (i % 8 == 0) {
                std::cout << " ";
            }
            if (i < bytesLeft) {
                std::cout << " " << std::setw(2) << std::hex << (unsigned int)packet[offset + i];
            } else {
                std::cout << "   ";
            }
        }
        std::cout << "\t";
        for (unsigned int i = 0; i < bytesLeft; ++i) {
            int byte = packet[offset + i];
            if (std::isprint(byte)) {
                std::cout << packet[offset + i];
            } else {
                std::cout << ".";
            }
        }
        offset += bytesPerLine;
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

/**
 * Processes TCP packet
 * @param source Source IP address/hostname
 * @param destination Destination IP address/hostname
 * @param packet Captured packet
 * @param size Packet size
 * @param headerSize Size of headers
 */
void processTcp(const std::string &source, const std::string &destination, const u_char *packet, unsigned int size, unsigned int headerSize) {
    const struct tcphdr *tcpHeader = (struct tcphdr *) &packet[headerSize];
    uint16_t sourcePort = ntohs(tcpHeader->source);
    uint16_t destinationPort = ntohs(tcpHeader->dest);
    std::cout << source << ":" << std::dec << sourcePort << " > " << destination << ":" << std::dec << destinationPort << std::endl;
    printPacket(packet, size);
}

/**
 * Processes UDP datagram
 * @param source Source IP address/hostname
 * @param destination Destination IP address/hostname
 * @param packet Captured packet
 * @param size Packet size
 * @param headerSize Size of headers
 */
void processUdp(const std::string &source, const std::string &destination, const u_char *packet, unsigned int size, unsigned int headerSize) {
    const struct udphdr *udpHeader = (struct udphdr *) &packet[headerSize];
    uint16_t sourcePort = ntohs(udpHeader->source);
    uint16_t destinationPort = ntohs(udpHeader->dest);
    std::cout << source << ":" << std::dec << sourcePort << " > " << destination << ":" << std::dec << destinationPort << std::endl;
    printPacket(packet, size);
}

/**
 * Processes IPv4 packet
 * @param packet Captured packet
 * @param size Packet size
 * @param headerSize Size of headers
 */
void processIpv4(const u_char *packet, unsigned int size, unsigned int headerSize) {
    const struct ip *ipHeader = (ip*) &packet[headerSize];
    std::string source = resolvePtr(AF_INET, &(ipHeader->ip_src));
    std::string destination = resolvePtr(AF_INET, &(ipHeader->ip_dst));
    headerSize += sizeof(ip);
    auto nextLayer = ipHeader->ip_p;
    switch (nextLayer) {
        case IPPROTO_TCP: {
            processTcp(source, destination, packet, size, headerSize);
            break;
        }
        case IPPROTO_UDP: {
            processUdp(source, destination, packet, size, headerSize);
            break;
        }
        default:
            std::cerr << "Unknown IPv4 protocol: " << std::to_string(nextLayer) << std::endl;
            break;
    }
}

/**
 * Processes IPv6 packet
 * @param packet Captured packet
 * @param size Packet size
 * @param headerSize Size of headers
 */
void processIpv6(const u_char *packet, unsigned int size, unsigned int headerSize) {
    const struct ip6_hdr *ipHeader = (ip6_hdr *) &packet[headerSize];
    std::string source = resolvePtr(AF_INET6, &(ipHeader->ip6_src));
    std::string destination = resolvePtr(AF_INET6, &(ipHeader->ip6_dst));
    headerSize += sizeof(struct ip6_hdr);
    auto nextLayer = ipHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    switch (nextLayer) {
        case IPPROTO_TCP:
            processTcp(source, destination, packet, size, headerSize);
            break;
        case IPPROTO_UDP:
            processUdp(source, destination, packet, size, headerSize);
            break;
        default:
            std::cerr << "Unknown IPv6 protocol: " << std::to_string(nextLayer) << std::endl;
            break;
    }
}

/**
 * Processes captured packet by PCAP
 * @param user User args
 * @param header Packet header
 * @param data Packet data
 */
void processPacket(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {
    printTime(header->ts);
    unsigned int size = header->len;
    const struct ether_header *ethernetHeader = (struct ether_header*) data;
    unsigned int headerSize = sizeof(struct ether_header);
    auto etherType = ntohs(ethernetHeader->ether_type);
    if (etherType == ETHERTYPE_IP) {
        processIpv4(data, size, headerSize);
    } else if (etherType == ETHERTYPE_IPV6) {
        processIpv6(data, size, headerSize);
    }
}

/**
 * Composes PCAP filter
 * @param tcp TCP support
 * @param udp UDP support
 * @param ports Ports
 * @return PCAP filter expression
 */
std::string composePcapFilter(bool tcp, bool udp, const std::vector<uint16_t> &ports) {
    std::string expr;
    if ((!tcp && !udp) || (tcp && udp)) {
        expr.append("(tcp or udp)");
    } else if (tcp) {
        expr.append("tcp");
    } else {
        expr.append("udp");
    }
    std::string portExpr;
    bool first = true;
    for (auto port: ports) {
        if (first) {
            portExpr.append("port ").append(std::to_string(port));
            first = false;
        } else {
            portExpr.append(" or port ").append(std::to_string(port));
        }
    }
    if (!ports.empty()) {
        expr.append(" and (").append(portExpr).append(")");
    }
    return expr;
}

/**
 * Main function
 * @param argc Argument count
 * @param argv Arguments
 * @return Execution status
 */
int main(int argc, char *argv[]) {
    bool tcp = false, udp = false;
    std::vector<uint16_t> ports;
    std::string interface;
    int count = 1;

    int option;
    std::string shortOptions = "hi:Ip:tun:";
    static struct option longOptions[] = {
            {"help", no_argument, nullptr, 'h'},
            {"interface", required_argument, nullptr, 'i'},
            {"list-interfaces", no_argument, nullptr, 'I'},
            {"port", required_argument, nullptr, 'p'},
            {"tcp", no_argument, nullptr, 't'},
            {"udp", no_argument, nullptr, 'u'},
            {"count", required_argument, nullptr, 'n'}
    };
    int optionIndex = 0;
    while((option = getopt_long(argc, argv, shortOptions.c_str(), longOptions, &optionIndex)) != -1) {
        switch (option) {
            case 'h':
                printHelp(std::cout, argv[0]);
                return EXIT_SUCCESS;
            case 'i':
                if (!interface.empty()) {
                    std::cerr << "Error: multiple interfaces are not supported." << std::endl;
                    return EXIT_FAILURE;
                }
                interface = optarg;
                break;
            case 'I':
                try {
                    listInterfaces();
                    return EXIT_SUCCESS;
                } catch (const std::exception &e) {
                    return EXIT_FAILURE;
                }
            case 'p':
                try {
                    int port = std::stoi(optarg);
                    if (port <= 0 || port > 65535) {
                        throw std::out_of_range("");
                    }
                    ports.push_back(port);
                } catch (const std::invalid_argument &e) {
                    std::cerr << "Error: bad port" << std::endl;
                    return EXIT_FAILURE;
                } catch (const std::out_of_range &e) {
                    std::cerr << "Error: bad port" << std::endl;
                    return EXIT_FAILURE;
                }
                break;
            case 't':
                tcp = true;
                break;
            case 'u':
                udp = true;
                break;
            case 'n':
                try {
                    count = std::stoi(optarg);
                    if (count < 0) {
                        throw std::out_of_range("");
                    }
                } catch (const std::invalid_argument &e) {
                    std::cerr << "Error: bad count" << std::endl;
                    return EXIT_FAILURE;
                } catch (const std::out_of_range &e) {
                    std::cerr << "Error: bad count" << std::endl;
                    return EXIT_FAILURE;
                }
                break;
            default:
                printHelp(std::cerr, argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (interface.empty()) {
        try {
            listInterfaces();
        } catch (const std::exception &e) {
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    char errorBuffer[PCAP_ERRBUF_SIZE] = "";
    pcap_t *handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Cannot open device " << interface << std::endl;
        return EXIT_FAILURE;
    }
    struct bpf_program filter = {};
    if (pcap_compile(handle, &filter, composePcapFilter(tcp, udp, ports).c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Invalid filter: " << pcap_geterr(handle) << std::endl;
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Error while setting filter: " << pcap_geterr(handle) << std::endl;
        return EXIT_FAILURE;
    }
    pcap_loop(handle, count, processPacket, nullptr);
    return EXIT_SUCCESS;
}
