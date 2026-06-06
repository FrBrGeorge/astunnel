# Async SSL TCP Packet-Tunneling Gateway

[![Python Test Suite](https://github.com/FrBrGeorge/astunnel/actions/workflows/test.yml/badge.svg)](https://github.com/FrBrGeorge/astunnel/actions)
[![Latest Release](https://img.shields.io/github/v/release/FrBrGeorge/astunnel)](https://github.com/FrBrGeorge/astunnel/releases)

A lightweight, high-performance, and zero-dependency Python `asyncio` package that establishes an SSL TCP connection to tunnel network payload packets inside customized stream-frames. 

Supports custom packet bunching/padding layouts, multi-client ID routing, and adaptive TLS security modes.

## Core Features

- **Asynchronous Multiplexing**: Built entirely on Python `asyncio` streams for extreme throughput.
- **Header Packaging**: IPv4 and IPv6 packets are passed as-is without extra header encapsulation (automatically parsed via their standard IP headers). Management and padding packets are prefixed with a 3-byte header (1-byte version/type and 2-byte payload size Big-Endian integer).
- **Dynamic Bunching**: Accumulates packets until:
  - Next packet exceeds the preferred TCP segment chunk size block.
  - Specified syncing timeout is triggered.
  - An incoming packet has a priority DSCP field (VoIP/SSH) demanding immediate flushing.
- **Three Padding Modes**: (`none`, `full`, `random`). String argument:
  - `none`: Disables padding.
  - `full`: Pads up to preferred bunch size with Junk packets of version 15.
  - `random`: Dynamic randomized floating pad size.
- **Multi-Client ID Routing**: Allocates and maps 4-octet Client IDs that mimic IPv4 addresses; translates Client IDs to payload-specific targets (e.g. IPv6 address strings).
- **Three SSL Security Models**:
  - `insecure`: Disables peer certification checks.
  - `trusted`: Checks the direct SHA256 cryptographic fingerprint of the self-signed certificate.
  - `secure`: Runs standard CAs verification checks.

## Installation

Install using pip:
```bash
pip install .
```

## Running the Terminal Nodes

### 1. Launch the Server
```bash
astunnel server --bind 0.0.0.0 --port 18443 --pem server.pem --padding full --timeout 0.25 --logfile server.log
```

### 2. Launch the Client
To run a client, specify the server address as a positional `host:port` argument:
```bash
astunnel client 127.0.0.1:18443 --client-id 10.0.0.5 --ssl-mode insecure --padding random --timeout 0.1 --logfile client.log
```

## Running Tests
Run unittest suite:
```bash
python -m unittest discover -s tests
```
