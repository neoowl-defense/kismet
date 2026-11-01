# Protected disconnect tests

On a network with management frame protection (802.11w), deauthentications and disassociations
to an associated client are protected: everything after the header is encrypted, so the reason
code can't be read.  `disconnect_pcaps.py` writes test pcaps (DLT 127, radiotap with channel and
dBm signal) for four scenarios:

- `pmf_protected`: an AP's own protected deauthentications, which must not raise
  `DEAUTHCODEINVALID`;
- `pmf_protected_disassoc`: protected disassociations, which must not raise
  `DISCONCODEINVALID`;
- `badreason`: an unprotected deauthentication with reason 99, which still must raise
  `DEAUTHCODEINVALID`;
- `router`: plain deauthentications with valid reasons, which raise nothing.

`run.sh` replays each scenario through a Kismet build, one instance per scenario, with
`DEAUTHCODEINVALID` and `DISCONCODEINVALID` turned on (both are off by default), and compares the
alerts with the expected ones:

    ./configure && make
    test/dot11_protected_disconnect/run.sh                   # all scenarios
    test/dot11_protected_disconnect/run.sh . pmf_protected   # one scenario

It needs Python 3.6 or later, and uses port 2598 on 127.0.0.1, or `DISCONNECT_TEST_PORT`, with
remote capture off, so it can run next to a Kismet server.
