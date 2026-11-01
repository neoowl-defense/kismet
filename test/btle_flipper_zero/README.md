# Flipper Zero tests

`flipper_pcaps.py` writes test pcaps (DLT 256, Bluetooth LE link layer with the pseudo-header)
of advertising devices, one scenario each:

- `stm32_public`, `stm32_random`: an 80:E1:26/27 address, which Flipper Zero firmware derives
  from its STM32WB chip ID, public and random.  80:E1:2x can't be a random address, so both
  match.
- `oui_public`, `oui_random`: the Flipper Devices OUI 0C:FA:22.  Only the public one matches,
  since a non-resolvable private address can begin with it by chance.
- `uuid_later`, `name_later`: the serial service UUID 0x3082, or a "Flipper " name, only in
  advertisements after the first second, so the device must be checked past its first packet.
- `company`: manufacturer data with the Flipper Devices company ID 0x0E29.
- `other`: another device, with nothing that should match.
- `burst`: four Flipper devices at once, more than the alert's 1/sec burst limit; each still
  gets its alert with a later packet.  Kismet skips a frame identical to one of the last
  `packet_dedup_size` packets, so each advertisement carries a changing byte; a real device's
  identical advertisements are only looked at again once that window has moved on.

`run.sh` replays each scenario through a Kismet build, one instance per scenario, and counts
the devices that raised `FLIPPERZERO`:

    ./configure && make
    test/btle_flipper_zero/run.sh                 # all scenarios
    test/btle_flipper_zero/run.sh . uuid_later    # one scenario

It uses port 2597 on 127.0.0.1, or `FLIPPER_TEST_PORT`, with remote capture off, so it can run
next to a Kismet server.  `burst` replays in real time and takes up to about 30 seconds.
