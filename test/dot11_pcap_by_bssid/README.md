# Per-BSSID pcapng stream test

`run.sh` starts a Kismet build with no data sources and opens the per-BSSID packet stream at
its documented URL, `/phy/phy80211/pcap/by-bssid/<BSSID>/packets.pcapng`. It passes when the
reply is HTTP 200 and begins with a pcapng section header block:

    ./configure && make
    test/dot11_pcap_by_bssid/run.sh

It uses port 2599 on 127.0.0.1, or `BSSID_TEST_PORT`, with remote capture off, so it can run
next to a Kismet server.
