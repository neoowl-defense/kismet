# BTLE PDU types test

`pdu_pcaps.py` writes a test pcap (DLT 256, Bluetooth LE link layer with the pseudo-header) of
three addresses: an advertiser sending ADV_IND and SCAN_RSP, a scanner sending only SCAN_REQ,
and an initiator sending only CONNECT_IND.

`run.sh` replays it through a Kismet build and checks `btle.device.pdu_types_seen` for each
address, bit n for PDU type n: 17 (ADV_IND and SCAN_RSP), 8 (SCAN_REQ) and 32 (CONNECT_IND).

    ./configure && make
    test/btle_pdu_types/run.sh

It uses port 2597 on 127.0.0.1, or `PDU_TEST_PORT`, with remote capture off, so it can run next
to a Kismet server.

A scanner or initiator address is the device looking for others, often a phone using a
throwaway random address for each scan; counting it as a device nearby overcounts.
