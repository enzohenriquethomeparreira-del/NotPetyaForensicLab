# Artifact formats

## Synthetic sector zero

The first 512 bytes of `disk.img` use the approved offsets:

| Offset | Length | Field |
|---:|---:|---|
| `0x000` | 3 | inert jump-shaped bytes `EB 3C 90` |
| `0x003` | 8 | ASCII `FORLAB01` |
| `0x00B` | 53 | synthetic BPB-shaped fixture |
| `0x040` | 16 | .NET GUID byte order |
| `0x050` | 32 | canonical-manifest SHA-256 |
| `0x070` | ≤144 | laboratory signature fixture |
| `0x100` | ≤184 | bounded UTF-8 message |
| `0x1B8` | 4 | little-endian synthetic disk ID |
| `0x1BE` | 64 | zeroed, non-bootable partition entries |
| `0x1FE` | 2 | `55 AA` marker |

The bytes are parsed as data by `LockScreenSimulator`; they are never executed or installed on bootable media.

## Custom forensic volume

`volume.img` begins with a 4096-byte `FLABVOL1` header, followed by fixed 512-byte directory entries, aligned data blocks, a 64 KiB journal, and a 64 KiB reserved escrow region. Each virtual file records its logical name, offsets, original SHA-256, nonce, GCM tag, and RSA-wrapped AES key.

AES-256-GCM uses a fresh 256-bit key and 96-bit nonce per virtual file. RSA-2048-OAEP-SHA256 wraps the AES key. The journal transitions through `Prepared`, `DataWritten`, and `Committed`; recovery produces `Restored`.

## Offline PCAPNG

The capture contains an Ethernet interface and deterministic synthetic TCP frames using only RFC 5737 addresses. Wireshark can decode the Ethernet/IPv4/TCP layers and identify the SMB2 protocol header. Command bodies and DCE/RPC data are deliberately non-operational marker payloads rather than complete protocol messages; IDS validation must key on the documented `LAB_*_FIXTURE` markers and staged TCP/SMB2-header sequence, not treat the file as a replayable SMB session. Request/response headers use paired message IDs. No socket API is referenced by the project.

## Telemetry

Every JSONL event records scenario ID, agent ID, monotonic sequence, UTC timestamp, normalized fields, prior hash, and current SHA-256. The current hash covers all fields except itself. ETW provider name: `ForensicLab-Agent`.
