#include "net.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

namespace {
void usage() {
    std::cerr << "usage: netstack --tap tap0 --ip 10.0.0.2/24 --mac 02:00:00:00:00:02\n";
}

std::uint16_t read_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void write_be16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}
}

int main(int argc, char** argv) {
    std::string tap_name = "tap0";
    std::string ip_cidr = "10.0.0.2/24";
    std::string mac_str = "02:00:00:00:00:02";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--tap" && i + 1 < argc) {
            tap_name = argv[++i];
        } else if (arg == "--ip" && i + 1 < argc) {
            ip_cidr = argv[++i];
        } else if (arg == "--mac" && i + 1 < argc) {
            mac_str = argv[++i];
        } else {
            usage();
            return 1;
        }
    }

    auto cidr = Cidr::parse(ip_cidr);
    auto mac = MacAddress::parse(mac_str);
    if (!cidr || !mac) {
        std::cerr << "invalid --ip or --mac\n";
        return 1;
    }

    try {
        TapDevice tap(tap_name, *cidr, *mac);
        std::cout << "tap " << tap.ifname() << " up at "
                  << cidr->ip.to_string() << "/" << int(cidr->prefix)
                  << " mac=" << mac->to_string() << "\n";

        while (true) {
            auto frame_bytes = tap.read_frame();
            if (!frame_bytes) {
                std::cerr << "read_frame failed\n";
                return 1;
            }
            if (frame_bytes->size() < 14) continue;

            auto eth = EthernetFrame::parse(*frame_bytes);
            if (!eth) continue;

            std::cout << "eth src=" << eth->src.to_string()
                      << " dst=" << eth->dst.to_string()
                      << " type=0x" << std::hex << eth->ether_type << std::dec
                      << " len=" << eth->payload.size() << "\n";

            if (eth->ether_type == 0x0806) {
                auto arp = ArpPacket::parse(eth->payload);
                if (!arp) continue;

                std::cout << "arp op=" << arp->oper
                          << " spa=" << arp->spa.to_string()
                          << " tpa=" << arp->tpa.to_string() << "\n";

                // Reply only when someone asks for our IP.
                if (arp->oper == 1 && arp->tpa.to_string() == cidr->ip.to_string()) {
                    ArpPacket reply;
                    reply.oper = 2;
                    reply.sha = *mac;
                    reply.spa = cidr->ip;
                    reply.tha = arp->sha;
                    reply.tpa = arp->spa;

                    EthernetFrame out;
                    out.dst = arp->sha;
                    out.src = *mac;
                    out.ether_type = 0x0806;
                    out.payload = reply.serialize();

                    if (!tap.write_frame(out.serialize())) {
                        std::cerr << "failed to write arp reply\n";
                    } else {
                        std::cout << "sent arp reply\n";
                    }
                }
                continue;
            }

            if (eth->ether_type == 0x0800) {
                auto ip = Ipv4Packet::parse(eth->payload);
                if (!ip) continue;

                std::cout << "ipv4 src=" << ip->src.to_string()
                          << " dst=" << ip->dst.to_string()
                          << " proto=" << int(ip->protocol) << "\n";

                if (ip->protocol == 1) {
                    auto icmp = IcmpPacket::parse(ip->payload);
                    if (!icmp) continue;

                    if (icmp->type == 8 && ip->dst.to_string() == cidr->ip.to_string()) {
                        IcmpPacket reply_icmp = *icmp;
                        reply_icmp.type = 0;

                        Ipv4Packet reply_ip;
                        reply_ip.ttl = 64;
                        reply_ip.protocol = 1;
                        reply_ip.src = cidr->ip;
                        reply_ip.dst = ip->src;
                        reply_ip.payload = reply_icmp.serialize();

                        EthernetFrame out;
                        out.dst = eth->src;
                        out.src = *mac;
                        out.ether_type = 0x0800;
                        out.payload = reply_ip.serialize();

                        if (!tap.write_frame(out.serialize())) {
                            std::cerr << "failed to write icmp reply\n";
                        } else {
                            std::cout << "sent icmp echo reply\n";
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
