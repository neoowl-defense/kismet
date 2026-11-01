#!/bin/bash
# Replay the protected disconnect test pcaps through a Kismet build and compare the alerts with
# the expected ones.  Each scenario runs in its own Kismet instance, since alerts are throttled
# by wall clock and a replay with realtime=false takes a fraction of a second.
#
# Usage: test/dot11_protected_disconnect/run.sh [kismet build dir] [scenario...]
# Needs python3 and curl; uses port $DISCONNECT_TEST_PORT (2598 by default) on 127.0.0.1, and no
# remote capture port or log files, so it can run next to a Kismet server.

HERE=$(cd "$(dirname "$0")" && pwd)
K=$(cd "${1:-$HERE/../..}" && pwd); shift
PORT=${DISCONNECT_TEST_PORT:-2598}
WORK=$(mktemp -d)
if [ -n "$KEEP" ]; then echo "work dir: $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

# Expected DEAUTHCODEINVALID / DISCONCODEINVALID alerts
expect() {
    case "$1" in
        router)                 echo "" ;;                    # a valid reason
        pmf_protected)          echo "" ;;                    # protected: the encrypted reason isn't judged
        pmf_protected_disassoc) echo "" ;;                    # likewise for disassociations
        badreason)              echo "DEAUTHCODEINVALID" ;;   # reason 99, unprotected
    esac
}
ORDER="router pmf_protected pmf_protected_disassoc badreason"

printf "httpd_bind_address=127.0.0.1\nhttpd_port=%s\nremote_capture_enabled=false\nenable_logging=false\nhttpd_username=disconnecttest\nhttpd_password=disconnecttest\nhelper_binary_path=%s\n" \
    "$PORT" "$K" > "$WORK/override.conf"
# DEAUTHCODEINVALID and DISCONCODEINVALID are off by default; turn them on to check protected
# frames don't trip them.  An override replaces every alert= line, so restate them all.
grep '^alert=' "$K/conf/kismet_alerts.conf" | \
    sed -e 's|^alert=DEAUTHCODEINVALID,.*|alert=DEAUTHCODEINVALID,10/min,1/sec|' \
        -e 's|^alert=DISCONCODEINVALID,.*|alert=DISCONCODEINVALID,10/min,1/sec|' >> "$WORK/override.conf"

fail=0
for sc in ${@:-$ORDER}; do
    mkdir -p "$WORK/$sc/home"
    python3 -I "$HERE/disconnect_pcaps.py" "$sc" "$WORK/$sc" > /dev/null || { echo "$sc: no pcap"; fail=1; continue; }

    (cd "$K" && exec ./kismet -f "$K/conf/kismet.conf" --homedir "$WORK/$sc/home" --confdir "$K/conf" \
        --datadir "$K" --no-ncurses --override "$WORK/override.conf" \
        -c "$WORK/$sc/$sc.pcap:type=pcapfile,realtime=false" > "$WORK/$sc/kismet.log" 2>&1) &
    pid=$!

    up=0
    for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:$PORT/ && { up=1; break; }; sleep 1; done
    if [ $up = 0 ]; then
        echo "FAIL $sc: Kismet did not start:"; tail -5 "$WORK/$sc/kismet.log"
        kill $pid 2>/dev/null; wait $pid 2>/dev/null; fail=1; continue
    fi
    sleep 5

    got=$(curl -s -u disconnecttest:disconnecttest http://127.0.0.1:$PORT/alerts/all_alerts.json | python3 -c '
import sys, json
names = {a["kismet.alert.header"] for a in json.load(sys.stdin)}
print(" ".join(sorted(n for n in names if n in ("DEAUTHCODEINVALID", "DISCONCODEINVALID"))))')

    kill $pid; wait $pid 2>/dev/null

    want=$(echo $(expect "$sc") | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "$want" ]; then
        echo "ok   $sc: ${got:--}"
    else
        echo "FAIL $sc: got '${got}', expected '${want}'"
        fail=1
    fi
done

exit $fail
