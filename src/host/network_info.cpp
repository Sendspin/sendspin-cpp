// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file network_info.cpp
/// @brief Host MAC detection: best-effort lookup of an active interface that carries a routable IP

#include "platform/network_info.h"

#include "platform/logging.h"

#include <cstdint>
#include <cstdio>
#include <set>
#include <string>

#if defined(_WIN32)
// winsock2.h must precede iphlpapi.h
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
// clang-format on

#include <vector>
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#if defined(__APPLE__)
#include <net/if_dl.h>  // sockaddr_dl, LLADDR
#else
#include <netpacket/packet.h>  // sockaddr_ll
#endif
#endif

namespace sendspin {

static const char* const TAG = "sendspin.network_info";

namespace {

/// @brief Size of a formatted MAC string buffer: "aa:bb:cc:dd:ee:ff" plus null terminator.
constexpr size_t MAC_STR_BUF_SIZE = 18;
/// @brief First octet of the IPv4 loopback range 127.0.0.0/8.
constexpr uint8_t IPV4_LOOPBACK_FIRST_OCTET = 127;
/// @brief High 16 bits of the IPv4 link-local range 169.254.0.0/16.
constexpr uint16_t IPV4_LINK_LOCAL_PREFIX = 0xA9FE;

/// @brief Formats six MAC octets as lowercase colon-separated text, or nullopt if all zero.
std::optional<std::string> format_mac(const uint8_t* mac) {
    bool all_zero = true;
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        return std::nullopt;
    }

    char buf[MAC_STR_BUF_SIZE];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
                  mac[4], mac[5]);
    return std::string(buf);
}

/// @brief True if `sa` is a routable (non-loopback, non-link-local) IPv4/IPv6 address.
bool is_routable_ip(const struct sockaddr* sa) {
    if (sa == nullptr) {
        return false;
    }
    if (sa->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const struct sockaddr_in*>(sa);
        const uint32_t addr = ntohl(in->sin_addr.s_addr);
        const uint8_t first = static_cast<uint8_t>(addr >> 24);
        const uint16_t first_two = static_cast<uint16_t>(addr >> 16);
        if (first == IPV4_LOOPBACK_FIRST_OCTET) {
            return false;  // loopback 127.0.0.0/8
        }
        if (first_two == IPV4_LINK_LOCAL_PREFIX) {
            return false;  // link-local 169.254.0.0/16
        }
        return true;
    }
    if (sa->sa_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) {
            return false;  // loopback ::1
        }
        if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
            return false;  // link-local fe80::/10
        }
        return true;
    }
    return false;
}

}  // namespace

#if defined(_WIN32)

std::optional<std::string> platform_get_interface_mac() {
    // A first call with no buffer reports the size it needs; retry if the adapter list grows
    // between calls.
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    std::vector<uint8_t> buffer;
    ULONG size = 0;
    ULONG err = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && err == ERROR_BUFFER_OVERFLOW; attempt++) {
        buffer.resize(size);
        err = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                                   reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (err != NO_ERROR) {
        SS_LOGW(TAG, "GetAdaptersAddresses failed (%lu); cannot auto-detect MAC address", err);
        return std::nullopt;
    }

    for (const auto* adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data());
         adapter != nullptr; adapter = adapter->Next) {
        // Skip loopback and adapters that are not up.
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        if (adapter->PhysicalAddressLength != 6) {
            continue;
        }
        // Only consider adapters that also have a routable IP address.
        bool routable = false;
        for (const auto* addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
            if (is_routable_ip(addr->Address.lpSockaddr)) {
                routable = true;
                break;
            }
        }
        if (!routable) {
            continue;
        }

        auto result = format_mac(adapter->PhysicalAddress);
        if (result.has_value()) {
            SS_LOGD(TAG, "auto-detected MAC %s on adapter %s", result->c_str(),
                    adapter->AdapterName);
            return result;
        }
    }
    return std::nullopt;
}

#else

std::optional<std::string> platform_get_interface_mac() {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0 || ifaddr == nullptr) {
        SS_LOGW(TAG, "getifaddrs failed; cannot auto-detect MAC address");
        return std::nullopt;
    }

    // First pass: collect interfaces that carry a routable IP. The MAC of such an interface is far
    // more likely to be the one a connection actually uses than an arbitrary up-and-running
    // interface (which on desktops includes bridges, VPN/utun, and AWDL links with no real route).
    std::set<std::string> routable_ifaces;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name != nullptr && is_routable_ip(ifa->ifa_addr)) {
            routable_ifaces.insert(ifa->ifa_name);
        }
    }

    std::optional<std::string> result;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr) {
            continue;
        }
        // Skip loopback and interfaces that are not up and running.
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }
        if ((ifa->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
            continue;
        }
        // Only consider interfaces that also have a routable IP address.
        if (routable_ifaces.find(ifa->ifa_name) == routable_ifaces.end()) {
            continue;
        }

#if defined(__APPLE__)
        if (ifa->ifa_addr->sa_family != AF_LINK) {
            continue;
        }
        auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (sdl->sdl_alen != 6) {
            continue;
        }
        result = format_mac(reinterpret_cast<const uint8_t*>(LLADDR(sdl)));
#else
        if (ifa->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }
        auto* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen != 6) {
            continue;
        }
        result = format_mac(sll->sll_addr);
#endif
        if (result.has_value()) {
            SS_LOGD(TAG, "auto-detected MAC %s on interface %s", result->c_str(), ifa->ifa_name);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return result;
}

#endif  // _WIN32

}  // namespace sendspin
