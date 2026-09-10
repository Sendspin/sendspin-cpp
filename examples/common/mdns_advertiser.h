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

/// @file mdns_advertiser.h
/// @brief Shared mDNS `_sendspin._tcp` service advertiser for the host examples (dns_sd.h)

#pragma once

#ifdef SENDSPIN_HAS_MDNS

#include <arpa/inet.h>
#include <dns_sd.h>

#include <cstdint>
#include <cstdio>
#include <string>

/// @brief Advertises a Sendspin service over mDNS so servers can discover the example
class MdnsAdvertiser {
public:
    ~MdnsAdvertiser() {
        stop();
    }

    bool start(const std::string& name, uint16_t port, const std::string& path) {
        TXTRecordRef txt;
        TXTRecordCreate(&txt, 0, nullptr);
        TXTRecordSetValue(&txt, "path", static_cast<uint8_t>(path.size()), path.c_str());
        TXTRecordSetValue(&txt, "name", static_cast<uint8_t>(name.size()), name.c_str());

        DNSServiceErrorType err = DNSServiceRegister(
            &service_ref_, 0, 0, name.c_str(), "_sendspin._tcp", nullptr, nullptr, htons(port),
            TXTRecordGetLength(&txt), TXTRecordGetBytesPtr(&txt), nullptr, nullptr);

        TXTRecordDeallocate(&txt);

        if (err != kDNSServiceErr_NoError) {
            fprintf(stderr, "Failed to register mDNS service: error %d\n", err);
            return false;
        }

        fprintf(stderr, "mDNS: Advertising _sendspin._tcp on port %u (name: %s)\n", port,
                name.c_str());
        return true;
    }

    void stop() {
        if (service_ref_ != nullptr) {
            DNSServiceRefDeallocate(service_ref_);
            service_ref_ = nullptr;
            fprintf(stderr, "mDNS: Service advertisement stopped\n");
        }
    }

private:
    DNSServiceRef service_ref_{nullptr};
};

#endif  // SENDSPIN_HAS_MDNS
