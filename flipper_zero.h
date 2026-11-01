/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __FLIPPER_ZERO_H__
#define __FLIPPER_ZERO_H__

#include "config.h"

#include <cctype>
#include <cstdint>
#include <memory>
#include <string>

#include "alertracker.h"
#include "fmt.h"
#include "macaddr.h"
#include "packet.h"

// Flipper Zero signatures in Bluetooth LE advertisements, shared by the Bluetooth and BTLE
// phys.  The serial profile of the official firmware and its forks advertises service UUID
// 0x3080 | body colour, from the public address 80:E1:<chip device ID>:<chip UID>, which
// stays across the forks; the official and Unleashed firmware also name the device
// "Flipper <name>".
namespace flipper_zero {

// What a device matched; kept in the device's flipper_zero field, so the values are part of
// the API, and new signatures only get new values.  A device keeps the first one it matches.
enum class signature : uint8_t {
    none = 0,
    service_uuid = 1,
    stm32_address = 2,
    oui = 3,
    company_id = 4,
    name = 5,
};

inline const char *describe(signature s) {
    switch (s) {
        case signature::service_uuid:
            return "the Flipper Zero service UUID 0x308x";
        case signature::stm32_address:
            return "an 80:E1:26/27 address, which Flipper Zero firmware derives from its "
                "STM32WB chip ID";
        case signature::oui:
            return "the Flipper Devices OUI 0C:FA:22";
        case signature::company_id:
            return "the Flipper Devices company ID 0x0E29";
        case signature::name:
            return "the 'Flipper ' name prefix of Flipper Zero firmware";
        case signature::none:
            break;
    }

    return "no Flipper Zero signature";
}

// The Flipper Zero is LE only and its address is public.  The top two bits of a random
// address are 11 (static), 01 (resolvable private) or 00 (non-resolvable private), never the
// 10 of 80:E1:26/27, so that prefix is checked whatever the address type; but a
// non-resolvable private address may happen to begin 0C:FA:22, so the OUI needs a public one.
inline signature address(const mac_addr& mac, bool public_addr) {
    if (mac.OUI() == 0x80E126 || mac.OUI() == 0x80E127)
        return signature::stm32_address;

    if (public_addr && mac.OUI() == 0x0CFA22)
        return signature::oui;

    return signature::none;
}

// Service UUIDs are kept as lowercase hex; the firmware sends 0x3080-0x3083
inline bool service_uuid(const std::string& uuid) {
    return uuid.length() == 4 && uuid.compare(0, 3, "308") == 0 &&
        std::isxdigit(static_cast<unsigned char>(uuid[3]));
}

// The Bluetooth SIG company ID of Flipper Devices, as lowercase hex; assigned, though
// current firmware doesn't advertise manufacturer data
inline bool company_id(const std::string& id) {
    return id == "0e29";
}

// The name the official and Unleashed firmware give the device
inline bool name(const std::string& devname) {
    return devname.compare(0, 8, "Flipper ") == 0;
}

// Which signature a device matches; when a packet shows several, the most specific
template<typename uuid_list>
signature match(const mac_addr& mac, bool public_addr, const std::string& devname,
        const std::string& company, const uuid_list& uuids) {
    for (const auto& u : uuids) {
        if (service_uuid(u))
            return signature::service_uuid;
    }

    auto addr = address(mac, public_addr);
    if (addr != signature::none)
        return addr;

    if (company_id(company))
        return signature::company_id;

    if (name(devname))
        return signature::name;

    return signature::none;
}

// Flag a device that matched a signature, so its alert is raised
template<typename tracked_device>
void flag(tracked_device& dev, signature sig) {
    if (sig == signature::none)
        return;

    dev.set_flipper_zero(static_cast<uint8_t>(sig));
    dev.flipper_alert_pending = true;
}

// Raise FLIPPERZERO for a flagged device once.  A rate limited alert stays pending and is
// retried with the device's next packet, so a burst of devices can't hide one.
template<typename tracked_device>
void raise_pending(tracked_device& dev, const std::shared_ptr<alert_tracker>& alertracker,
        int alert_ref, const std::shared_ptr<kis_packet>& in_pack, const mac_addr& source) {
    // potential_alert() first, so the text isn't formatted for a throttled alert
    if (!dev.flipper_alert_pending || !alertracker->potential_alert(alert_ref))
        return;

    if (alertracker->raise_alert(alert_ref, in_pack, mac_addr{}, source, mac_addr{}, mac_addr{},
            "FHSS", fmt::format("Bluetooth device matches a Flipper Zero signature ({}); "
                "Flipper Zero devices can generate BTLE packets which may cause a denial of "
                "service or other problems with some BTLE devices.",
                describe(static_cast<signature>(dev.get_flipper_zero())))) > 0)
        dev.flipper_alert_pending = false;
}

}

#endif
