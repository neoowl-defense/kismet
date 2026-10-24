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

#ifndef __DEVICE_TRACKER_V2_H__
#define __DEVICE_TRACKER_V2_H__

#include "config.h"

#include <memory>

#include "alertracker.h"
#include "devicetracker_component_v2.h"
#include "eventbus.h"
#include "globalregistry.h"
#include "kis_database.h"
#include "kis_mutex.h"
#include "packet.h"
#include "rrd_v2.h"
#include "streamtracker.h"
#include "timetracker.h"

class device_tracker_v2 : public lifetime_global, public kis_database,
    public deferred_startup, public std::enable_shared_from_this<device_tracker_v2> {
private:
    device_tracker_v2();

public:
    virtual ~device_tracker_v2();

    virtual void trigger_deferred_startup() override;

protected:
    kis_shared_mutex mutex_;

    std::shared_ptr<alert_tracker> alertracker;
    std::shared_ptr<event_bus> eventbus;
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<stream_tracker> streamtracker;
    std::shared_ptr<time_tracker> timetracker;

    void timetracker_event(int eventid);
    int common_tracker(const std::shared_ptr<kis_packet>&);

    // raw packet counts
    uint64_t num_packets_;
    uint64_t num_datapackets_;
    uint64_t num_errorpackets_;
    uint64_t num_filterpackets_;

    // per-phy-id counts
    std::unordered_map<int, uint64_t> phy_packets_;
    std::unordered_map<int, uint64_t> phy_datapackets_;
    std::unordered_map<int, uint64_t> phy_errorpackets_;
    std::unordered_map<int, uint64_t> phy_filterpackets_;

    // total packet history
    kis_rrd_v2<> packets_rrd_;

    // timeout of idle devices
    int device_idle_expiration_;
    int device_idle_timer_;

    // minimum number of packets for a device to eligible to be timed out
    size_t device_idle_min_packets_;

    // maximum number of devices
    size_t max_num_device_;
    int max_devices_timer_;

    // device storage timer id
    int device_storage_timer_;

    // last timestamp we removed a device
    time_t full_refresh_time_;

    bool track_history_cloud_;
    bool track_persource_history_;

    // immutable tracked vector which is never re-sorted and never has deleted
    // devices backfilled
    using device_immut_vec_iter_t_ = std::vector<kis_tracked_device_base_v2 *>::iterator;
    std::vector<kis_tracked_device_base_v2 *> immutable_traxked_vec_;

    // key->device map
    using device_map_t_ = ankerl::unordered_dense::map<device_key_v2, kis_tracked_device_base_v2 *>;
    using device_map_iter_t_ = device_map_t_::iterator;
    using device_map_citer_t_ = device_map_t_::const_iterator;
    device_map_t_ tracked_map_;

    // MAC address lookups are expensive without this additional index
    std::multimap<mac_addr, kis_tracked_device_base_v2 *> tracked_mac_multimap_;

public:
    static std::string event_new_phy() { return "NEW_PHY"; }
    static std::string event_new_device() { return "NEW_DEVICE"; }
};


#endif /* __DEVICE_TRACKER_V2_H__ */
