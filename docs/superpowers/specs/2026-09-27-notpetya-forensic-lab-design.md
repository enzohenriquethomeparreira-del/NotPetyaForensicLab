# NotPetya Forensic Lab Simulator — Design Specification

Date: 2026-09-27  
Status: Approved design, awaiting written-spec review  
Target: Windows 10/11 or Windows Server VM, .NET 8, C# 12

## 1. Purpose

Build a deterministic Windows forensic-lab simulator that creates artifacts analogous to a destructive ransomware/worm incident without implementing an operational exploit, credential theft, real lateral movement, raw-device modification, persistence, or NTFS encryption.

The deliverable must support analysis with ETW/Event Log, hexadecimal disk inspection, YARA-like signatures, PCAP/IDS tooling, entropy analysis, carving, key-recovery validation, and timeline reconstruction.

## 2. Non-goals and hard boundaries

The system must not:

- open `\\.\PhysicalDrive*`, `\\.\Harddisk*`, `\\?\Volume*`, mounted VHD/VHDX devices, removable media, UNC paths, or reparse-point targets;
- scan a real network, send SMB/DCE-RPC packets, authenticate to Windows shares, call remote SCM/WMI/WinRM, create services, or copy executables to another host;
- extract, replay, validate, or store real Windows credentials;
- enumerate or transform host NTFS files;
- replace the Windows shell, inhibit administrative controls, persist across reboot, or run as `SYSTEM`;
- execute bytes stored in the synthetic sector-zero fixture;
- accept arbitrary commands, scripts, plugins, reflection-loaded assemblies, or process paths from a manifest.

These restrictions are architectural invariants, not optional configuration.

## 3. Architecture

The solution contains the following projects:

```text
src/
  LabController/
  WindowsLabAgent/
  DiskImageSimulator/
  LateralMovementSimulator/
  HoneypotCrypto/
  LockScreenSimulator/
  ForensicTelemetry/
  Shared.Contracts/
tests/
  Unit/
  Integration/
  SafetyInvariants/
  GoldenArtifacts/
```

`LabController` creates and signs a scenario manifest, invokes agents explicitly installed in authorized VMs, collects artifacts, and assembles a timeline. `WindowsLabAgent` validates the environment and manifest before dispatching a fixed set of operations. Artifact modules never receive unrestricted paths or arbitrary executable instructions.

## 4. Scenario manifest

The manifest is canonical JSON signed with RSA-PSS/SHA-256. Signature verification uses a pinned controller public key shipped separately from the scenario document. Canonicalization follows RFC 8785 semantics or an equivalent deterministic implementation covered by golden tests.

Required claims:

- schema version;
- scenario UUID;
- agent UUID and VM fingerprint;
- issued-at and expiry UTC timestamps;
- nonce unique to the scenario;
- exact absolute paths of allowed regular `.img`, `.pcapng`, `.etl`, `.evtx`, JSON, and CSV files;
- maximum volume size, transformed-block count, total bytes, and runtime;
- documentation-only IP addresses used as values in offline PCAP records;
- enabled operations from the compile-time operation registry;
- controller certificate thumbprint;
- detached signature metadata.

Validation is fail-closed. It rejects expired or future-dated manifests, unknown fields in security-critical objects, duplicate JSON keys, invalid signatures, reused nonces, non-canonical paths, relative paths, path traversal, UNC/device syntax, existing reparse points, mounted-volume targets, unsupported operations, excessive limits, and a VM fingerprint mismatch.

## 5. Agent state machine

States:

```text
Created -> Validating -> Ready -> Executing -> Collecting -> Completed
                      \-> Rejected
                                  Executing -> Aborted -> Collecting
```

Transitions are monotonic and recorded through a hash-chained telemetry writer. A transition requires the expected prior state and is guarded by an interlocked compare/exchange. Cancellation, timeout, or a limit violation moves execution to `Aborted`; artifact collection still runs.

The compile-time operation registry contains only:

- `CreateForensicVolume`;
- `WriteSyntheticSectorZero`;
- `GenerateOfflinePcap`;
- `EncryptVirtualFiles`;
- `RenderLockScreen`;
- `CollectArtifacts`;
- `RestoreFromEscrow`.

## 6. Telemetry and evidence integrity

Each event contains scenario ID, agent ID, sequence number, UTC timestamp, event type, normalized fields, prior-event SHA-256, and current-event SHA-256. ETW is emitted through a dedicated `EventSource`; an append-only JSON Lines copy is the authoritative portable record.

Events never contain plaintext AES keys, RSA private material, decrypted fixture content, or real credentials. Binary outputs receive SHA-256 manifests. The collector verifies the hash chain and artifact hashes before constructing JSON/CSV timelines.

## 7. Synthetic sector-zero artifact

`DiskImageSimulator` operates only on an allowed, unmounted regular file. The image is created with an exclusive handle. The module revalidates the final handle path and file identity after opening to prevent path replacement races.

The first 512 bytes use this fixed layout:

| Offset | Length | Field |
|---:|---:|---|
| `0x000` | 3 | inert jump-shaped signature bytes |
| `0x003` | 8 | laboratory OEM identifier |
| `0x00B` | 53 | synthetic BPB-shaped fields |
| `0x040` | 16 | scenario UUID bytes |
| `0x050` | 32 | manifest SHA-256 |
| `0x070` | variable | scenario-specific signature fixture |
| `0x100` | variable | UTF-8 diagnostic message, length-bounded |
| `0x1B8` | 4 | synthetic disk identifier |
| `0x1BE` | 64 | non-bootable synthetic partition entries |
| `0x1FE` | 2 | `55 AA` marker |

The builder uses a zero-initialized 512-byte buffer, explicit little-endian writes, and overlap/range assertions. The jump-shaped bytes are data only and are never installed on bootable media. Message rendering occurs in `LockScreenSimulator`, which parses the image as a data format.

`SectorWriter` requires an exact 512-byte input, seeks only within the allowed image, writes with a `RandomAccess`/safe file handle API, flushes the file, reads the sector back, and verifies its hash. Before/after sector copies, hexadecimal diffs, offset maps, region entropy, and hashes are preserved.

## 8. Offline lateral-movement artifact

`LateralMovementSimulator` creates a PCAPNG file without opening a socket. It serializes a deterministic conversation representing:

1. TCP establishment;
2. SMB2 Negotiate request/response;
3. SMB2 Session Setup with fictitious, non-reusable identity material;
4. SMB2 Tree Connect to a textual `IPC$` fixture;
5. named-pipe-shaped operation;
6. DCE/RPC-shaped bind and service-manager fixture records;
7. fictitious service-create request and configured result;
8. teardown.

Only RFC 5737 documentation addresses are permitted. Authentication fields, signatures, identifiers, and handles are fixtures that cannot authenticate to Windows. The PCAP generator references no networking assemblies and is tested to prove that no socket is created. Wireshark/TShark decoding is verified against golden artifacts.

## 9. Forensic volume and in-place transformation

`HoneypotCrypto` transforms blocks inside a custom `forensic-volume.img`, not host files. The image contains a header, virtual allocation table, virtual directory, data blocks, slack space, circular journal, and recovery package region.

For every virtual file:

1. record block offsets, lengths, and original SHA-256;
2. generate a 256-bit AES key and 96-bit nonce using Windows CNG-backed cryptography;
3. encrypt the virtual-file contents with AES-256-GCM;
4. overwrite the same allocated blocks inside the image;
5. persist the 128-bit authentication tag and nonce in the virtual directory entry;
6. wrap the AES key using RSA-2048-OAEP with SHA-256;
7. write the recovery record before marking the journal transaction committed;
8. flush, read back, and verify ciphertext/tag metadata;
9. emit hashes and a block-level transformation map.

The implementation uses `AesGcm` and `RSA` providers backed by Windows CNG where available; it does not call undocumented native interfaces. Key buffers use short lifetimes and are zeroed with `CryptographicOperations.ZeroMemory` in `finally` paths. The recovery escrow is generated and verified before any block transformation begins.

The format supports deterministic fixture content but fresh cryptographic randomness. Tests validate successful restoration, authentication failure on altered ciphertext/tag, interruption recovery, slack-space behavior, and carving-oriented before/after snapshots.

## 10. Memory, offset, and I/O rules

- checked arithmetic is mandatory for every offset-plus-length computation;
- reads and writes must be exact-length loops and treat short I/O as failure;
- all binary structures define byte order explicitly;
- maximum image and block sizes come from compile-time ceilings that a manifest may only reduce;
- pooled buffers containing plaintext or key material are cleared before return;
- no unsafe pointers or unmanaged allocation are required for the first implementation;
- file handles use least privilege, exclusive sharing where appropriate, and deterministic disposal;
- path safety is rechecked after handle acquisition to mitigate time-of-check/time-of-use races.

## 11. Lock-screen fixture

The lock-screen application reads only scenario status and sector-fixture data. It may use full-screen presentation, but it remains closable, does not replace Explorer, does not alter policy or startup configuration, and exposes an administrative exit route. Its countdown is a display element with no destructive callback.

## 12. Verification strategy

### Unit tests

- canonical manifest serialization and signature validation;
- state-transition legality and concurrency;
- sector layout, endianness, overlap, bounds, and message truncation;
- virtual-volume allocation and journal semantics;
- AES-GCM round trips, tamper rejection, and RSA-OAEP unwrap;
- hash-chain construction and verification.

### Integration tests

- controller-to-agent signed-scenario execution;
- sector write/readback on temporary `.img` files;
- complete virtual-volume transform and restoration;
- PCAPNG decoding with TShark when installed;
- ETW and JSONL correlation;
- cancellation and simulated power-loss checkpoints.

### Safety-invariant tests

- reject all Windows device-path forms and UNC paths;
- reject links, junctions, reparse points, mounted images, and removable media;
- prove no networking API is used by the offline PCAP module;
- prove host fixture directories are never enumerated or transformed;
- prove recovery material is valid before the first overwrite;
- fuzz manifest JSON and every binary parser;
- run under a standard user token and reject elevation-dependent behavior.

### Golden artifacts

Version-controlled golden files cover sector zero, PCAPNG conversations, event chains, virtual-volume layouts, and recovery manifests. Tests compare structure and normalized fields while excluding cryptographically random bytes.

## 13. Delivery stages

1. Shared contracts, manifest canonicalization/signatures, validator, state machine, and telemetry.
2. Safe image-path validator, sector builder/writer, and golden-sector tests.
3. Custom forensic-volume format, escrow, AES-GCM/RSA-OAEP transformation, restore path, and interruption tests.
4. Offline PCAPNG conversation generator and decoder tests.
5. Controller orchestration, collector, timeline builder, and lock-screen fixture.
6. Windows VM integration tests and forensic-analysis guide.

## 14. Acceptance criteria

- all unit, integration, safety, and golden-artifact tests pass on Windows with .NET 8;
- a complete scenario produces sector-zero, virtual-volume, PCAPNG, ETW/JSONL, hash-manifest, recovery, and timeline artifacts;
- the encrypted virtual files restore byte-for-byte;
- the PCAPNG opens in Wireshark/TShark and displays the intended staged conversation;
- no raw device, mounted volume, network socket, remote-management API, host-file encryption, persistence, or privilege-escalation operation exists in the implementation;
- static inspection and tests confirm the hard boundaries cannot be relaxed through scenario configuration.
