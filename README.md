# Decrypt BIS PDUs

``bis_crack`` decrypts BLE Audio BIS PDUs.
This is a small standalone tool that heavily relies on code ripped out of ZephyrsOS' bluetooth subsystem.
The CCM and CMAC implementation comes from the tinycrypt library that is being maintained as part of zephyr.
Some of the ripped-out parts have been slightly modified to remove dependencies on the zephyr codebase.
Most of the actually new code resides in ``bt_bis.c`` and of course ``main.c``.
The AES NI code is taken from ``https://github.com/sebastien-riou/aes-brute-force`` and slightly modified to integrate with the tinycrypt CCM/CMAC implementation.

# Usage

To crack a Broadcast_Code a encrypted PDU, its packet counter and a BIGInfo are needed.
All of this can be dumped with the [Auracast Hacker's Toolkit](https://github.com/auracast-research/auracast-hackers-toolkit) and extracted from the log with the ``log_extract.sh`` script from this repo.

```
Usage: biscrack [OPTIONS]...
  -m, --mode=MODE                 Mode: numeric or wordlist
  -p, --pdu=FILE                  Encrypted PDU file
  -b, --biginfo=FILE              BIGInfo file
  -c, --payload-count=COUNTER     Payload counter
  -w, --wordlist=FILE             Wordlist file (required for wordlist mode)
  -l, --bc-length=LENGTH          Broadcast Code hex byte length (required for numeric mode)
  -t, --threads=NUM               Number of threads to use

Help options:
  -?, --help                      Show this help message
      --usage                     Display brief usage message
```
