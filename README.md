# Airgap

> Air-gapped NEAR transaction signing suite built with Rust and iced.

[中文](./README.zh-CN.md)

Airgap is a dual-device signing system for the NEAR blockchain.  
It separates **transaction construction (online)** from **offline signing**, using files for explicit, user-controlled data transfer.

**Private keys never touch a networked environment.**

---

## Architecture

Airgap is composed of two independent applications running on separate devices:

- **airgap-online (hot machine)**  
  Runs on a network-connected device.  
  Responsible for fetching on-chain data (nonce, recent block hash), constructing unsigned transactions, and broadcasting signed transactions to the network.

- **airgap-offline (cold machine)**  
  Runs on an isolated, air-gapped device.  
  Responsible for parsing incoming transactions, displaying human-readable details for user verification, and signing transactions using private keys that never leave the device.

Data moves between the two devices as structured files:

- Online → Offline: unsigned transaction request file
- Offline → Online: signed transaction response file

The offline device never connects to the network and never receives any executable input—only structured transaction data for verification and signing.

---

## Flow

```
airgap-online:
fetch chain state → build unsigned tx → export request file

airgap-offline:
import request file → verify → sign → export response file

airgap-online:
import response file → broadcast
```

---

## Project Structure

```
airgap/
├── airgap-core      # shared logic (tx / encoding / parsing)
├── airgap-online    # hot machine (builder + broadcaster)
├── airgap-offline   # cold machine (signer)
└── Cargo.toml
```

---

## Modules

### `airgap-core`

- Transaction model (NEAR)
- Encoding / decoding (borsh / base64)
- File payload schema
- Human-readable transaction parsing

---

### `airgap-online`

- RPC interaction
- Nonce & block hash fetching
- Transaction construction
- Request file export
- Response file import
- Broadcasting signed transaction

---

### `airgap-offline`

- Request file import
- Transaction inspection (critical)
- Signing (ed25519)
- Response file export

---

## Security Model

Key isolation via device separation.

### Mitigates

- Private key exfiltration
- Malware on online machine
- Clipboard injection
- Executable input on the offline machine

### Requires

- User verification on offline device
- Fresh block hash (short signing window)

---

## Run

```bash
cargo run -p airgap-online
cargo run -p airgap-offline
```

Local app data is stored under `~/.airgap/`:

```text
~/.airgap/airgap-online/db
~/.airgap/airgap-offline/db
~/.airgap/airgap-online/out
~/.airgap/airgap-offline/out
```

---

## Summary

```
airgap-online builds transactions
airgap-offline signs them
files carry unsigned requests and signed responses
```
