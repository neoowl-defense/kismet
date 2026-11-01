#!/bin/bash
# Replay the address type test pcap through a Kismet build and check each device's
# btle.device.address_type.
#
# Usage: test/btle_address_type/run.sh [kismet build dir]
# Needs python3 and curl; uses port $ADDRESS_TEST_PORT (2598 by default) on 127.0.0.1, and no
# remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd)
PORT=${ADDRESS_TEST_PORT:-2598}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=addrtest\nhttpd_password=addrtest\nhelper_binary_path=%s\n" \
    "$PORT" "$K" > "$WORK/override.conf"
mkdir -p "$WORK/home"
python3 -I "$HERE/address_pcaps.py" "$WORK/address.pcap" || { echo "FAIL: no pcap"; exit 1; }

(cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/home" --confdir "$K/conf" \
    --datadir "$K" --no-ncurses --override "$WORK/override.conf" \
    -c "$WORK/address.pcap:type=pcapfile,realtime=false" > "$WORK/kismet.log" 2>&1) &
pid=$!

# The address type each device should have: 1 public, 2 random
want="00:1B:DC:12:34:56=1 C6:11:22:33:44:55=2"
got=
for i in $(seq 1 30); do
    sleep 1
    got=$(curl -s -u addrtest:addrtest -d 'json={"fields":["kismet.device.base.macaddr","btle.device/btle.device.address_type"]}' \
        http://127.0.0.1:$PORT/devices/views/phy-BTLE/devices.json 2>/dev/null | python3 -c '
import sys, json
try:
    devs = json.load(sys.stdin)
except ValueError:
    sys.exit()
print(" ".join(sorted("%s=%s" % (d["kismet.device.base.macaddr"], d.get("btle.device.address_type"))
                      for d in devs)))' 2>/dev/null)
    [ "$got" = "$want" ] && break
done

kill $pid 2>/dev/null; wait $pid 2>/dev/null

if [ "$got" = "$want" ]; then
    echo "ok   address types: $got"
else
    echo "FAIL address types: got '$got', expected '$want'"
    tail -5 "$WORK/kismet.log"
    exit 1
fi
