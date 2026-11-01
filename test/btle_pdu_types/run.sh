#!/bin/bash
# Replay the PDU type test pcap through a Kismet build and check each device's
# btle.device.pdu_types_seen.
#
# Usage: test/btle_pdu_types/run.sh [kismet build dir]
# Needs python3 and curl; uses port $PDU_TEST_PORT (2597 by default) on 127.0.0.1, and no
# remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd)
PORT=${PDU_TEST_PORT:-2597}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

LOGIN=pdutest:pdutest   # the test Kismet's web login, local only
printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=pdutest\nhttpd_password=pdutest\nhelper_binary_path=%s\n" \
    "$PORT" "$K" > "$WORK/override.conf"
mkdir -p "$WORK/home"
python3 -I "$HERE/pdu_pcaps.py" "$WORK/pdu.pcap" || { echo "FAIL: no pcap"; exit 1; }

(cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/home" --confdir "$K/conf" \
    --datadir "$K" --no-ncurses --override "$WORK/override.conf" \
    -c "$WORK/pdu.pcap:type=pcapfile,realtime=false" > "$WORK/kismet.log" 2>&1) &
pid=$!

# The PDU types each address sent, bit n for type n: the advertiser ADV_IND (0) and SCAN_RSP
# (4), the scanner SCAN_REQ (3), the initiator CONNECT_IND (5)
want="00:1B:DC:12:34:56=17 4A:11:22:33:44:55=8 5B:66:77:88:99:AA=32"
got=
for i in $(seq 1 30); do
    sleep 1
    got=$(curl -s -u "$LOGIN" -d 'json={"fields":["kismet.device.base.macaddr","btle.device/btle.device.pdu_types_seen"]}' \
        http://127.0.0.1:$PORT/devices/views/phy-BTLE/devices.json 2>/dev/null | python3 -c '
import sys, json
try:
    devs = json.load(sys.stdin)
except ValueError:
    sys.exit()
print(" ".join(sorted("%s=%s" % (d["kismet.device.base.macaddr"], d.get("btle.device.pdu_types_seen"))
                      for d in devs)))' 2>/dev/null)
    [ "$got" = "$want" ] && break
done

kill $pid 2>/dev/null; wait $pid 2>/dev/null

if [ "$got" = "$want" ]; then
    echo "ok   PDU types seen: $got"
else
    echo "FAIL PDU types seen: got '$got', expected '$want'"
    tail -5 "$WORK/kismet.log"
    exit 1
fi
