#!/bin/bash
# Check that the per-BSSID pcapng stream answers at its documented URL,
# /phy/phy80211/pcap/by-bssid/<BSSID>/packets.pcapng.
#
# Usage: test/dot11_pcap_by_bssid/run.sh [kismet build dir]
# Needs curl and od; uses port $BSSID_TEST_PORT (2599 by default) on 127.0.0.1, with no data
# sources, remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd)
PORT=${BSSID_TEST_PORT:-2599}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

LOGIN=bssidtest:bssidtest   # the test Kismet's web login, local only
printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=bssidtest\nhttpd_password=bssidtest\nhelper_binary_path=%s\n" \
    "$PORT" "$K" > "$WORK/override.conf"
mkdir -p "$WORK/home"

(cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/home" --confdir "$K/conf" \
    --datadir "$K" --no-ncurses --override "$WORK/override.conf" > "$WORK/kismet.log" 2>&1) &
pid=$!

up=0
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:$PORT/ && { up=1; break; }; sleep 1; done

fail=0
if [ $up = 0 ]; then
    echo "FAIL: Kismet did not start:"; tail -5 "$WORK/kismet.log"; fail=1
else
    # The stream stays open until the connection closes; the start of it is enough
    code=$(curl -s -m 2 -o "$WORK/stream" -w "%{http_code}" -u "$LOGIN" \
        "http://127.0.0.1:$PORT/phy/phy80211/pcap/by-bssid/00:11:22:33:44:55/packets.pcapng")
    # A pcapng file begins with a section header block, type 0x0A0D0D0A
    magic=$(od -An -tx1 -N4 "$WORK/stream" 2>/dev/null | tr -d ' \n')
    if [ "$code" = 200 ] && [ "$magic" = 0a0d0d0a ]; then
        echo "ok   by-bssid packets.pcapng: HTTP $code, pcapng"
    else
        echo "FAIL by-bssid packets.pcapng: HTTP '$code', first bytes '$magic'"
        fail=1
    fi
fi

kill $pid 2>/dev/null; wait $pid 2>/dev/null
exit $fail
