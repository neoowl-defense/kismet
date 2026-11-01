# Bluetooth address type test

`address_pcaps.py` writes a test pcap (DLT 256, Bluetooth LE link layer with the pseudo-header)
of two devices advertising, one from a public address and one from a random one, as the TxAdd
bit of each advertisement says.

`run.sh` replays it through a Kismet build and checks `btle.device.address_type` for each
device (1 public, 2 random):

    ./configure && make
    test/btle_address_type/run.sh

It uses port 2598 on 127.0.0.1, or `ADDRESS_TEST_PORT`, with remote capture off, so it can run
next to a Kismet server.

The Linux HCI capture source reports the address type the kernel gives each device, which
fills `bluetooth.device.address_type`; that path needs a Bluetooth controller, so it isn't
covered here.
