#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};

    static std::optional<MacAddress> parse(const std::string& s);
    std::string to_string() const;
};

struct Ipv4Address {
    std::array<std::uint8_t, 4> bytes{};

    static std::optional<Ipv4Address> parse(const std::string& s);
    std::string to_string() const;
};

struct Cidr {
    Ipv4Address ip{};
    std::uint8_t prefix = 0;

    static std::optional<Cidr> parse(const std::string& s);
};

struct EthernetFrame {
    MacAddress dst{};
    MacAddress src{};
    std::uint16_t ether_type = 0;
    std::vector<std::uint8_t> payload;

    static std::optional<EthernetFrame> parse(std::span<const std::uint8_t> bytes);
    std::vector<std::uint8_t> serialize() const;
};

struct ArpPacket {
    std::uint16_t htype = 1;
    std::uint16_t ptype = 0x0800;
    std::uint8_t hlen = 6;
    std::uint8_t plen = 4;
    std::uint16_t oper = 1;

    MacAddress sha{};
    Ipv4Address spa{};
    MacAddress tha{};
    Ipv4Address tpa{};

    static std::optional<ArpPacket> parse(std::span<const std::uint8_t> bytes);
    std::vector<std::uint8_t> serialize() const;
};

struct Ipv4Packet {
    std::uint8_t ttl = 64;
    std::uint8_t protocol = 1;
    Ipv4Address src{};
    Ipv4Address dst{};
    std::vector<std::uint8_t> payload;

    static std::optional<Ipv4Packet> parse(std::span<const std::uint8_t> bytes);
    std::vector<std::uint8_t> serialize() const;
};

struct IcmpPacket {
    std::uint8_t type = 8;
    std::uint8_t code = 0;
    std::vector<std::uint8_t> payload;

    static std::optional<IcmpPacket> parse(std::span<const std::uint8_t> bytes);
    std::vector<std::uint8_t> serialize() const;
};

class TapDevice {
public:
    TapDevice(const std::string& ifname, const Cidr& cidr, const MacAddress& mac);
    ~TapDevice();

    TapDevice(const TapDevice&) = delete;
    TapDevice& operator=(const TapDevice&) = delete;

    int fd() const noexcept { return fd_; }
    const std::string& ifname() const noexcept { return ifname_; }
    const Cidr& cidr() const noexcept { return cidr_; }
    const MacAddress& mac() const noexcept { return mac_; }

    std::optional<std::vector<std::uint8_t>> read_frame();
    bool write_frame(std::span<const std::uint8_t> frame);

private:
    int fd_ = -1;
    std::string ifname_;
    Cidr cidr_{};
    MacAddress mac_{};

    void bring_up();
};

std::uint16_t checksum16(std::span<const std::uint8_t> bytes);
std::uint16_t ipv4_header_checksum(const std::vector<std::uint8_t>& header);
std::uint16_t udp_tcp_checksum_ipv4(Ipv4Address src, Ipv4Address dst, std::uint8_t protocol, std::span<const std::uint8_t> segment);
