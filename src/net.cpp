#include "net.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {
std::uint16_t read_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void write_be16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}

void write_be32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}

std::optional<std::array<std::uint8_t, 6>> parse_mac_bytes(const std::string& s) {
    std::array<std::uint8_t, 6> out{};
    unsigned int b[6];
    if (std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
                    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return std::nullopt;
    }
    for (int i = 0; i < 6; ++i) out[i] = static_cast<std::uint8_t>(b[i]);
    return out;
}

std::optional<std::array<std::uint8_t, 4>> parse_ipv4_bytes(const std::string& s) {
    std::array<std::uint8_t, 4> out{};
    unsigned int b[4];
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]) != 4) {
        return std::nullopt;
    }
    for (int i = 0; i < 4; ++i) out[i] = static_cast<std::uint8_t>(b[i]);
    return out;
}
}

std::optional<MacAddress> MacAddress::parse(const std::string& s) {
    auto bytes = parse_mac_bytes(s);
    if (!bytes) return std::nullopt;
    MacAddress m;
    m.bytes = *bytes;
    return m;
}

std::string MacAddress::to_string() const {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return buf;
}

std::optional<Ipv4Address> Ipv4Address::parse(const std::string& s) {
    auto bytes = parse_ipv4_bytes(s);
    if (!bytes) return std::nullopt;
    Ipv4Address ip;
    ip.bytes = *bytes;
    return ip;
}

std::string Ipv4Address::to_string() const {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  bytes[0], bytes[1], bytes[2], bytes[3]);
    return buf;
}

std::optional<Cidr> Cidr::parse(const std::string& s) {
    auto slash = s.find('/');
    if (slash == std::string::npos) return std::nullopt;
    auto ip = Ipv4Address::parse(s.substr(0, slash));
    if (!ip) return std::nullopt;
    int prefix = std::stoi(s.substr(slash + 1));
    if (prefix < 0 || prefix > 32) return std::nullopt;
    Cidr c;
    c.ip = *ip;
    c.prefix = static_cast<std::uint8_t>(prefix);
    return c;
}

std::uint16_t checksum16(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    while (i + 1 < bytes.size()) {
        sum += static_cast<std::uint16_t>((bytes[i] << 8) | bytes[i + 1]);
        i += 2;
    }
    if (i < bytes.size()) {
        sum += static_cast<std::uint16_t>(bytes[i] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t ipv4_header_checksum(const std::vector<std::uint8_t>& header) {
    return checksum16(header);
}

std::uint16_t udp_tcp_checksum_ipv4(Ipv4Address src, Ipv4Address dst, std::uint8_t protocol, std::span<const std::uint8_t> segment) {
    std::vector<std::uint8_t> pseudo;
    pseudo.insert(pseudo.end(), src.bytes.begin(), src.bytes.end());
    pseudo.insert(pseudo.end(), dst.bytes.begin(), dst.bytes.end());
    pseudo.push_back(0);
    pseudo.push_back(protocol);
    write_be16(pseudo, static_cast<std::uint16_t>(segment.size()));
    pseudo.insert(pseudo.end(), segment.begin(), segment.end());
    if (pseudo.size() % 2 != 0) pseudo.push_back(0);
    return checksum16(pseudo);
}

std::optional<EthernetFrame> EthernetFrame::parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 14) return std::nullopt;
    EthernetFrame f;
    std::copy_n(bytes.data(), 6, f.dst.bytes.begin());
    std::copy_n(bytes.data() + 6, 6, f.src.bytes.begin());
    f.ether_type = read_be16(bytes.data() + 12);
    f.payload.assign(bytes.begin() + 14, bytes.end());
    return f;
}

std::vector<std::uint8_t> EthernetFrame::serialize() const {
    std::vector<std::uint8_t> out;
    out.reserve(14 + payload.size());
    out.insert(out.end(), dst.bytes.begin(), dst.bytes.end());
    out.insert(out.end(), src.bytes.begin(), src.bytes.end());
    write_be16(out, ether_type);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::optional<ArpPacket> ArpPacket::parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 28) return std::nullopt;
    ArpPacket a;
    a.htype = read_be16(bytes.data());
    a.ptype = read_be16(bytes.data() + 2);
    a.hlen = bytes[4];
    a.plen = bytes[5];
    a.oper = read_be16(bytes.data() + 6);
    if (a.hlen != 6 || a.plen != 4) return std::nullopt;
    std::copy_n(bytes.data() + 8, 6, a.sha.bytes.begin());
    std::copy_n(bytes.data() + 14, 4, a.spa.bytes.begin());
    std::copy_n(bytes.data() + 18, 6, a.tha.bytes.begin());
    std::copy_n(bytes.data() + 24, 4, a.tpa.bytes.begin());
    return a;
}

std::vector<std::uint8_t> ArpPacket::serialize() const {
    std::vector<std::uint8_t> out;
    out.reserve(28);
    write_be16(out, htype);
    write_be16(out, ptype);
    out.push_back(hlen);
    out.push_back(plen);
    write_be16(out, oper);
    out.insert(out.end(), sha.bytes.begin(), sha.bytes.end());
    out.insert(out.end(), spa.bytes.begin(), spa.bytes.end());
    out.insert(out.end(), tha.bytes.begin(), tha.bytes.end());
    out.insert(out.end(), tpa.bytes.begin(), tpa.bytes.end());
    return out;
}

std::optional<Ipv4Packet> Ipv4Packet::parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 20) return std::nullopt;
    std::uint8_t version_ihl = bytes[0];
    if ((version_ihl >> 4) != 4) return std::nullopt;
    std::uint8_t ihl = (version_ihl & 0x0f) * 4;
    if (bytes.size() < ihl) return std::nullopt;
    Ipv4Packet p;
    p.ttl = bytes[8];
    p.protocol = bytes[9];
    std::copy_n(bytes.data() + 12, 4, p.src.bytes.begin());
    std::copy_n(bytes.data() + 16, 4, p.dst.bytes.begin());
    p.payload.assign(bytes.begin() + ihl, bytes.end());
    return p;
}

std::vector<std::uint8_t> Ipv4Packet::serialize() const {
    std::vector<std::uint8_t> header;
    header.reserve(20);
    header.push_back(0x45);
    header.push_back(0);
    write_be16(header, static_cast<std::uint16_t>(20 + payload.size()));
    write_be16(header, 0);
    write_be16(header, 0);
    header.push_back(ttl);
    header.push_back(protocol);
    write_be16(header, 0);
    header.insert(header.end(), src.bytes.begin(), src.bytes.end());
    header.insert(header.end(), dst.bytes.begin(), dst.bytes.end());
    auto csum = ipv4_header_checksum(header);
    header[10] = static_cast<std::uint8_t>((csum >> 8) & 0xff);
    header[11] = static_cast<std::uint8_t>(csum & 0xff);
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

std::optional<IcmpPacket> IcmpPacket::parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4) return std::nullopt;
    IcmpPacket p;
    p.type = bytes[0];
    p.code = bytes[1];
    p.payload.assign(bytes.begin() + 4, bytes.end());
    return p;
}

std::vector<std::uint8_t> IcmpPacket::serialize() const {
    std::vector<std::uint8_t> out;
    out.reserve(4 + payload.size());
    out.push_back(type);
    out.push_back(code);
    write_be16(out, 0);
    out.insert(out.end(), payload.begin(), payload.end());
    auto csum = checksum16(out);
    out[2] = static_cast<std::uint8_t>((csum >> 8) & 0xff);
    out[3] = static_cast<std::uint8_t>(csum & 0xff);
    return out;
}

TapDevice::TapDevice(const std::string& ifname, const Cidr& cidr, const MacAddress& mac)
    : ifname_(ifname), cidr_(cidr), mac_(mac) {
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        throw std::runtime_error("failed to open /dev/net/tun");
    }

    struct ifreq ifr {};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());

    if (::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("TUNSETIFF failed; container likely needs /dev/net/tun and NET_ADMIN");
    }

    bring_up();
}

TapDevice::~TapDevice() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

void TapDevice::bring_up() {
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) throw std::runtime_error("socket(AF_INET, SOCK_DGRAM) failed");

    auto close_sock = [&]() {
        if (sock >= 0) ::close(sock);
        sock = -1;
    };

    struct ifreq ifr {};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname_.c_str());

    if (::ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close_sock();
        throw std::runtime_error("SIOCGIFFLAGS failed");
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (::ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        close_sock();
        throw std::runtime_error("SIOCSIFFLAGS failed");
    }

    close_sock();
}

std::optional<std::vector<std::uint8_t>> TapDevice::read_frame() {
    std::vector<std::uint8_t> buf(2048);
    ssize_t n = ::read(fd_, buf.data(), buf.size());
    if (n < 0) return std::nullopt;
    buf.resize(static_cast<std::size_t>(n));
    return buf;
}

bool TapDevice::write_frame(std::span<const std::uint8_t> frame) {
    ssize_t n = ::write(fd_, frame.data(), frame.size());
    return n == static_cast<ssize_t>(frame.size());
}
