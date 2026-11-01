#!/bin/bash
# Replay the Flipper Zero test pcaps through a Kismet build and compare the FLIPPERZERO alerts
# with the expected ones.  Each scenario runs in its own Kismet instance, since alerts are
# throttled by wall clock.
#
# Usage: test/btle_flipper_zero/run.sh [kismet build dir] [scenario...]
# Needs python3 and curl; uses port $FLIPPER_TEST_PORT (2597 by default) on 127.0.0.1, and no
# remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd); shift
PORT=${FLIPPER_TEST_PORT:-2597}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

# How many devices should raise FLIPPERZERO
expect() {
    case "$1" in
        stm32_public) echo 1 ;;
        stm32_random) echo 1 ;;    # 80:E1:2x can't be a random address
        oui_public)   echo 1 ;;
        oui_random)   echo 0 ;;    # a random address may begin 0C:FA:22 by chance
        uuid_later)   echo 1 ;;    # the UUID comes after the first advertisements
        name_later)   echo 1 ;;
        company)      echo 1 ;;
        other)        echo 0 ;;
        burst)        echo 4 ;;    # four at once, past the 1/sec alert burst limit
    esac
}
ORDER="stm32_public stm32_random oui_public oui_random uuid_later name_later company other burst"

LOGIN=fliptest:fliptest   # the test Kismet's web login, local only
printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=fliptest\nhttpd_password=fliptest\nhelper_binary_path=%s\n" \
    "$PORT" "$K" > "$WORK/override.conf"

fail=0
for sc in ${@:-$ORDER}; do
    mkdir -p "$WORK/$sc/home"
    python3 -I "$HERE/flipper_pcaps.py" "$sc" "$WORK/$sc" > /dev/null || { echo "$sc: no pcap"; fail=1; continue; }

    # The burst plays in real time, so the alert rate limit sees the devices spread out the
    # way they would be, and is read until all its devices alerted or the pcap is over; the
    # rest replay as fast as they can
    if [ "$sc" = burst ]; then realtime=true; settle=25; else realtime=false; settle=5; fi
    want=$(expect "$sc")

    (cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/$sc/home" --confdir "$K/conf" \
        --datadir "$K" --no-ncurses --override "$WORK/override.conf" \
        -c "$WORK/$sc/$sc.pcap:type=pcapfile,realtime=$realtime" > "$WORK/$sc/kismet.log" 2>&1) &
    pid=$!

    up=0
    for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:$PORT/ && { up=1; break; }; sleep 1; done
    if [ $up = 0 ]; then
        echo "FAIL $sc: Kismet did not start:"; tail -5 "$WORK/$sc/kismet.log"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null; fail=1; continue
    fi
    # Devices that raised FLIPPERZERO; scenarios expecting none wait the whole time
    for i in $(seq 1 $settle); do
        sleep 1
        got=$(curl -s -u "$LOGIN" http://127.0.0.1:$PORT/alerts/all_alerts.json | python3 -c '
import sys, json
macs = {a["kismet.alert.source_mac"] for a in json.load(sys.stdin)
        if a["kismet.alert.header"] == "FLIPPERZERO"}
print(len(macs))')
        [ "$want" != 0 ] && [ "$got" = "$want" ] && break
    done

    kill $pid; wait $pid 2>/dev/null

    if [ "$got" = "$want" ]; then
        echo "ok   $sc: $got"
    else
        echo "FAIL $sc: got '${got}' devices, expected '${want}'"
        fail=1
    fi
done

exit $fail
