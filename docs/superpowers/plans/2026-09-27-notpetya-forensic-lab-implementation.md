# NotPetya Forensic Lab Simulator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a compile-ready .NET 8 Windows forensic-lab solution that produces safe sector-zero, encrypted virtual-volume, offline PCAPNG, lock-screen, and tamper-evident telemetry artifacts.

**Architecture:** A console `WindowsLabAgent` validates a signed canonical manifest and dispatches a compile-time operation registry. Focused class libraries create only regular-file artifacts: `DiskImageSimulator` writes a synthetic 512-byte sector, `HoneypotCrypto` transforms a custom virtual volume, and `LateralMovementSimulator` serializes an offline SMB-shaped PCAPNG without sockets. A WPF lock-screen fixture consumes read-only scenario state.

**Tech Stack:** C# 12, .NET 8, `net8.0-windows`, WPF, `System.Text.Json`, `System.Security.Cryptography` backed by Windows CNG, `EventSource`, xUnit, Microsoft.NET.Test.Sdk.

**Spec:** `docs/superpowers/specs/2026-09-27-notpetya-forensic-lab-design.md`

## Global Constraints

- Target Windows 10/11 or Windows Server with .NET 8; compile with nullable reference types and implicit usings enabled.
- Never open physical-drive, hard-disk, volume-device, UNC, removable-media, mounted-image, junction, symlink, or reparse-point targets.
- Never open a network socket or call SCM, WMI, WinRM, PowerShell, remote registry, or arbitrary process execution.
- Never enumerate or transform host NTFS fixture trees; cryptography operates only inside the custom `forensic-volume.img` format.
- Never run as `SYSTEM`, request elevation, install persistence, replace Explorer, or inhibit administrative controls.
- Use checked arithmetic for offsets and lengths, exact-length I/O, explicit little-endian binary fields, bounded allocations, and deterministic disposal.
- Clear plaintext/key buffers with `CryptographicOperations.ZeroMemory` and generate/verify recovery escrow before the first in-place block write.
- Restrict synthetic PCAP endpoints to RFC 5737 documentation ranges and write packets only to a regular `.pcapng` file.
- Every operation emits hash-chained JSONL telemetry; ETW must not contain secrets or plaintext content.

## Review Focus

- Path replacement between validation and open: revalidate final handle identity and reject reparse/device targets after acquisition.
- Partial write, cancellation, or simulated power loss: journal must permit deterministic resume or rollback without losing escrow.
- Malformed, duplicate-key, non-canonical, expired, or replayed manifests: validator must fail closed before artifact mutation.
- Integer overflow and overlapping sector/volume regions: builders must reject before allocating or writing.
- PCAP parser differentials: TShark/Wireshark must decode golden packets while no runtime networking API is referenced or invoked.

---

## File map

```text
NotPetyaForensicLab.sln
Directory.Build.props
src/
  Shared.Contracts/
    Shared.Contracts.csproj
    AgentState.cs
    AllowedOperation.cs
    ScenarioManifest.cs
    ManifestLimits.cs
    ArtifactPaths.cs
    OperationRequest.cs
    OperationResult.cs
    ValidationResult.cs
    ForensicEvent.cs
  ForensicTelemetry/
    ForensicTelemetry.csproj
    LabEventSource.cs
    HashChainWriter.cs
    ArtifactHasher.cs
  WindowsLabAgent/
    WindowsLabAgent.csproj
    Program.cs
    AgentHost.cs
    AgentStateMachine.cs
    ManifestValidator.cs
    CanonicalJson.cs
    PinnedKeyProvider.cs
    NonceStore.cs
    EnvironmentAttestor.cs
    SafeArtifactPath.cs
    OperationDispatcher.cs
  DiskImageSimulator/
    DiskImageSimulator.csproj
    SyntheticMbrLayout.cs
    SyntheticMbrBuilder.cs
    SectorWriter.cs
    SectorDiffReporter.cs
  HoneypotCrypto/
    HoneypotCrypto.csproj
    ForensicVolumeLayout.cs
    ForensicVolumeHeader.cs
    VirtualFileEntry.cs
    ForensicVolume.cs
    RecoveryEscrow.cs
    CngKeyProvider.cs
    InPlaceBlockTransformer.cs
    VolumeRestorer.cs
  LateralMovementSimulator/
    LateralMovementSimulator.csproj
    DocumentationAddress.cs
    PcapNgWriter.cs
    EthernetIpv4TcpBuilder.cs
    SmbConversationModel.cs
    OfflineConversationGenerator.cs
  LockScreenSimulator/
    LockScreenSimulator.csproj
    App.xaml
    App.xaml.cs
    MainWindow.xaml
    MainWindow.xaml.cs
    ScenarioViewModel.cs
    SectorMessageReader.cs
tests/
  Shared.Tests/
  Agent.Tests/
  DiskImage.Tests/
  HoneypotCrypto.Tests/
  LateralMovement.Tests/
  SafetyInvariants.Tests/
  Integration.Tests/
```

## Task 1: Solution scaffold and shared contracts

**Files:**
- Create: `NotPetyaForensicLab.sln`, `Directory.Build.props`
- Create: `src/Shared.Contracts/*`
- Create: `tests/Shared.Tests/Shared.Tests.csproj`, `tests/Shared.Tests/ContractTests.cs`

**Interfaces:**
- Produces: immutable records `ScenarioManifest`, `ManifestLimits`, `ArtifactPaths`, `OperationRequest`, `OperationResult`, `ValidationResult`, and `ForensicEvent`; enums `AgentState` and `AllowedOperation`.

- [ ] **Step 1: Scaffold the solution and projects** with `dotnet new`, add project references, enable `TreatWarningsAsErrors`, nullable annotations, deterministic builds, and C# 12.
- [ ] **Step 2: Write failing contract tests** named `Manifest_rejects_empty_identity_fields`, `Limits_reject_negative_values`, and `Allowed_operations_round_trip_as_strings`.
- [ ] **Step 3: Run** `dotnet test tests/Shared.Tests/Shared.Tests.csproj`; expect failing assertions or missing types.
- [ ] **Step 4: Implement the immutable contract records** with constructor validation and `JsonStringEnumConverter` configuration exposed by `ContractJson.CreateOptions()`.
- [ ] **Step 5: Run** `dotnet test tests/Shared.Tests/Shared.Tests.csproj`; expect all tests to pass.
- [ ] **Step 6: Commit** with `git commit -m "feat: add solution and shared contracts"` when working in a Git repository.

## Task 2: Hash-chained telemetry

**Files:**
- Create: `src/ForensicTelemetry/*`
- Create: `tests/Shared.Tests/HashChainWriterTests.cs`

**Interfaces:**
- Consumes: `ForensicEvent` from Task 1.
- Produces: `HashChainWriter.AppendAsync(string eventType, IReadOnlyDictionary<string,string> fields, CancellationToken) -> ValueTask<ForensicEvent>` and `ArtifactHasher.ComputeSha256Async(SafeFileHandle, CancellationToken) -> ValueTask<byte[]>`.

- [ ] **Step 1: Write failing tests** `First_event_uses_zero_previous_hash`, `Second_event_links_first_hash`, `Tampered_jsonl_fails_verification`, and `Concurrent_append_preserves_monotonic_sequence`.
- [ ] **Step 2: Run** the four tests and confirm failure.
- [ ] **Step 3: Implement canonical event serialization, SHA-256 chaining, append-only JSONL, and `LabEventSource`** without recording secrets or content bytes.
- [ ] **Step 4: Run** `dotnet test tests/Shared.Tests/Shared.Tests.csproj`; expect pass.
- [ ] **Step 5: Commit** `feat: add tamper-evident forensic telemetry`.

## Task 3: Canonical signed-manifest validation

**Files:**
- Create: `src/WindowsLabAgent/CanonicalJson.cs`, `ManifestValidator.cs`, `PinnedKeyProvider.cs`, `NonceStore.cs`
- Create: `tests/Agent.Tests/ManifestValidatorTests.cs`, `tests/Agent.Tests/ManifestFixtures.cs`

**Interfaces:**
- Consumes: `ScenarioManifest`, pinned RSA public key, current UTC time, VM fingerprint, nonce store.
- Produces: `ManifestValidator.ValidateAsync(ReadOnlyMemory<byte> json, ReadOnlyMemory<byte> signature, CancellationToken) -> ValueTask<ValidationResult>`.

- [ ] **Step 1: Write failing tests** for a valid RSA-PSS/SHA-256 signature and rejection of duplicate JSON keys, unknown critical fields, invalid signature, expired/future timestamp, replayed nonce, fingerprint mismatch, unsupported operation, excessive limit, and malformed UTF-8.
- [ ] **Step 2: Run** `dotnet test tests/Agent.Tests/Agent.Tests.csproj --filter ManifestValidator`; expect failure.
- [ ] **Step 3: Implement duplicate-key detection with `Utf8JsonReader`, deterministic property ordering in `CanonicalJson`, RSA-PSS verification, temporal checks, and atomic nonce persistence.**
- [ ] **Step 4: Run the validator tests**; expect pass.
- [ ] **Step 5: Commit** `feat: validate signed canonical scenario manifests`.

## Task 4: Artifact-path and environment safety

**Files:**
- Create: `src/WindowsLabAgent/SafeArtifactPath.cs`, `EnvironmentAttestor.cs`
- Create: `tests/SafetyInvariants.Tests/PathInvariantTests.cs`, `tests/SafetyInvariants.Tests/EnvironmentAttestorTests.cs`

**Interfaces:**
- Produces: `SafeArtifactPath.OpenNewRegularFile(string manifestPath, long maximumLength) -> SafeFileHandle`; `SafeArtifactPath.OpenExistingRegularFile(string manifestPath, FileAccess access) -> SafeFileHandle`; `EnvironmentAttestor.Attest() -> ValidationResult`.

- [ ] **Step 1: Write failing Windows-only tests** rejecting all device prefixes, UNC, relative/traversal paths, directory handles, reparse points, symlinks, junctions, mounted-image paths, removable drives, `SYSTEM` identity, and path replacement after initial validation.
- [ ] **Step 2: Run** the safety tests on Windows; expect failure.
- [ ] **Step 3: Implement lexical validation, full-path canonicalization, drive-type checks, reparse checks before/after handle acquisition, final-handle path validation, file identity capture, exclusive sharing, and standard-user attestation.**
- [ ] **Step 4: Run** `dotnet test tests/SafetyInvariants.Tests/SafetyInvariants.Tests.csproj`; expect pass or explicit skip for unavailable VM-only cases.
- [ ] **Step 5: Commit** `feat: enforce artifact path and environment boundaries`.

## Task 5: Agent lifecycle and dispatch

**Files:**
- Create: `src/WindowsLabAgent/AgentStateMachine.cs`, `OperationDispatcher.cs`, `AgentHost.cs`, `Program.cs`
- Create: `tests/Agent.Tests/AgentStateMachineTests.cs`, `OperationDispatcherTests.cs`

**Interfaces:**
- Consumes: validation/attestation results and a fixed `IReadOnlyDictionary<AllowedOperation, IOperationHandler>`.
- Produces: legal transitions `Idle -> Armed -> Running -> Collecting -> Completed` and any nonterminal state -> `Aborted`.

- [ ] **Step 1: Write failing state-machine tests** for all legal and illegal transitions plus concurrent transition attempts.
- [ ] **Step 2: Write failing dispatch tests** proving only enum-backed registry entries execute and unregistered operations fail closed.
- [ ] **Step 3: Run** `dotnet test tests/Agent.Tests/Agent.Tests.csproj`; expect failure.
- [ ] **Step 4: Implement atomic state transitions and compile-time registry dispatch; do not load types, assemblies, scripts, or commands from the manifest.**
- [ ] **Step 5: Run** agent tests; expect pass.
- [ ] **Step 6: Commit** `feat: add safety-locked agent lifecycle`.

## Task 6: Synthetic sector-zero artifact

**Files:**
- Create: `src/DiskImageSimulator/SyntheticMbrLayout.cs`, `SyntheticMbrBuilder.cs`, `SectorWriter.cs`, `SectorDiffReporter.cs`
- Create: `tests/DiskImage.Tests/SyntheticMbrBuilderTests.cs`, `tests/DiskImage.Tests/SectorWriterTests.cs`

**Interfaces:**
- Consumes: `scenarioId`, canonical manifest hash, bounded message, ordinary image `SafeFileHandle`.
- Produces: exact 512-byte sector and machine-readable diff report.

- [ ] **Step 1: Write failing layout tests** asserting every offset/length and that all partition entries remain zero.
- [ ] **Step 2: Write failing boundary tests** for max UTF-8 message, overflow, non-512 input, short stream, and checked disk-ID derivation.
- [ ] **Step 3: Run** `dotnet test tests/DiskImage.Tests/DiskImage.Tests.csproj`; expect failure.
- [ ] **Step 4: Implement `SyntheticMbrBuilder.Build(...)`** with explicit little-endian writes, non-bootable synthetic jump-shaped bytes, lab OEM marker, GUID, manifest hash, message, disk ID, empty partition table, and `55 AA` marker.
- [ ] **Step 5: Implement exact-offset `SectorWriter.WriteAsync`** with ordinary-file handle only, length precondition, flush, and read-back verification.
- [ ] **Step 6: Implement `SectorDiffReporter`** to emit changed byte ranges and before/after SHA-256.
- [ ] **Step 7: Run** disk-image tests; expect pass.
- [ ] **Step 8: Commit** `feat: add synthetic sector-zero forensic artifact`.

## Task 7: Offline PCAPNG byte writer

**Files:**
- Create: `src/LateralMovementSimulator/PcapNgWriter.cs`, `EthernetIpv4TcpBuilder.cs`
- Create: `tests/LateralMovement.Tests/PcapNgWriterTests.cs`

**Interfaces:**
- Produces: section header, Ethernet interface, and enhanced-packet blocks into an ordinary file handle.

- [ ] **Step 1: Write failing tests** for block lengths, endianness magic, snap length, padded packet data, mirrored trailing lengths, IPv4/TCP checksums, and rejection of oversized packet records.
- [ ] **Step 2: Run** `dotnet test tests/LateralMovement.Tests/LateralMovement.Tests.csproj --filter PcapNgWriter`; expect failure.
- [ ] **Step 3: Implement only buffer serialization and exact-length file writes; do not reference `System.Net.Sockets` or any live transport API.**
- [ ] **Step 4: Run the writer tests**; expect pass.
- [ ] **Step 5: Commit** `feat: add deterministic offline pcapng writer`.

## Task 8: Custom forensic volume

**Files:**
- Create: `src/HoneypotCrypto/ForensicVolumeLayout.cs`, `ForensicVolumeHeader.cs`, `VirtualFileEntry.cs`, `ForensicVolume.cs`, `VolumeJournal.cs`
- Create: `tests/HoneypotCrypto.Tests/ForensicVolumeTests.cs`

**Interfaces:**
- Produces: `ForensicVolume.CreateAsync(SafeFileHandle, ForensicVolumeOptions, CancellationToken) -> Task<ForensicVolume>`; `AddVirtualFileAsync(string logicalName, ReadOnlyMemory<byte> content, CancellationToken) -> ValueTask<VirtualFileEntry>`; exact-offset block read/write methods internal to the assembly.

- [ ] **Step 1: Write failing tests** for header magic/version, non-overlapping regions, checked size arithmetic, allocation-table exhaustion, duplicate logical names, bounded UTF-8 names, deterministic fixture layout, slack initialization, and reopen validation.
- [ ] **Step 2: Run** `dotnet test tests/HoneypotCrypto.Tests/HoneypotCrypto.Tests.csproj --filter ForensicVolume`; expect failure.
- [ ] **Step 3: Implement the header, virtual directory, allocation table, blocks, slack, journal, and escrow regions with exact-length I/O.**
- [ ] **Step 4: Run the volume tests**; expect pass.
- [ ] **Step 5: Commit** `feat: add bounded custom forensic volume format`.

## Task 9: Escrow and CNG-backed cryptographic transformation

**Files:**
- Create: `src/HoneypotCrypto/CngKeyProvider.cs`, `RecoveryEscrow.cs`, `InPlaceBlockTransformer.cs`, `VolumeRestorer.cs`
- Create: `tests/HoneypotCrypto.Tests/CryptoTransformTests.cs`, `tests/HoneypotCrypto.Tests/RecoveryTests.cs`

**Interfaces:**
- Produces: `CngKeyProvider.GenerateFileMaterial() -> FileKeyMaterial`; `RecoveryEscrow.PrepareAndVerifyAsync(...) -> ValueTask<VerifiedEscrow>`; `InPlaceBlockTransformer.TransformAsync(ForensicVolume, VirtualFileEntry, VerifiedEscrow, CancellationToken) -> ValueTask<TransformResult>`; `VolumeRestorer.RestoreAsync(...) -> ValueTask<RestoreResult>`.

- [ ] **Step 1: Write failing tests** for AES-256 key length, 96-bit nonce, 128-bit tag, RSA-2048 OAEP-SHA256 wrap/unwrap, fresh material per virtual file, tamper rejection, wrong-key rejection, and plaintext/key-buffer zeroing hooks.
- [ ] **Step 2: Write failing transaction tests** proving escrow verification occurs before the first overwrite, journal `Prepared -> DataWritten -> Committed` transitions, cancellation recovery, simulated power loss at each checkpoint, in-place block offsets, unchanged neighboring blocks, and byte-for-byte restoration.
- [ ] **Step 3: Run** the crypto tests; expect failure.
- [ ] **Step 4: Implement key generation through .NET cryptographic providers, require Windows CNG provider identity where exposed, verify escrow round-trip, and clear transient spans in `finally`.**
- [ ] **Step 5: Implement chunked AES-GCM records sized to bounded volume blocks, same-block overwrite, tag/nonce directory update, journal flushes, and authenticated restore.**
- [ ] **Step 6: Run** all HoneypotCrypto tests; expect pass.
- [ ] **Step 7: Commit** `feat: add recoverable in-place virtual-volume encryption`.

## Task 10: Offline PCAPNG and SMB-shaped conversation

**Files:**
- Create: `src/LateralMovementSimulator/DocumentationAddress.cs`, `PcapNgWriter.cs`, `EthernetIpv4TcpBuilder.cs`, `SmbConversationModel.cs`, `OfflineConversationGenerator.cs`
- Create: `tests/LateralMovement.Tests/PcapNgWriterTests.cs`, `tests/LateralMovement.Tests/ConversationTests.cs`, `tests/LateralMovement.Tests/Golden/offline-conversation.pcapng`

**Interfaces:**
- Produces: `OfflineConversationGenerator.GenerateAsync(SafeFileHandle output, ConversationScenario scenario, CancellationToken) -> ValueTask<ConversationResult>`.

- [ ] **Step 1: Write failing tests** rejecting non-RFC-5737 addresses and asserting PCAPNG section/interface/enhanced-packet blocks, deterministic timestamps, valid checksums, TCP sequence progression, and staged Negotiate/SessionSetup/TreeConnect/pipe/DCE-RPC-shaped/service-fixture/teardown records.
- [ ] **Step 2: Add a safety test** that scans the compiled module's references and IL for `System.Net.Sockets.Socket`, `TcpClient`, `UdpClient`, HTTP clients, process execution, and remote-management APIs; expect zero matches.
- [ ] **Step 3: Run** the tests; expect failure.
- [ ] **Step 4: Implement the file-only PCAPNG serializer and minimal deterministic Ethernet/IPv4/TCP packet builder using byte buffers only.**
- [ ] **Step 5: Implement the conversation model with fictitious, non-reusable authentication/handle fields and an explicit laboratory marker.**
- [ ] **Step 6: Validate the golden file with `tshark -r <file> -V` when installed and assert expected protocol-stage labels; otherwise mark only the external decoder check skipped.**
- [ ] **Step 7: Run** all lateral-movement tests; expect pass.
- [ ] **Step 8: Commit** `feat: generate offline SMB-shaped forensic PCAPNG`.

## Task 11: Safe WPF lock-screen fixture

**Files:**
- Create: `src/LockScreenSimulator/*`
- Create: `tests/Integration.Tests/SectorMessageReaderTests.cs`, `tests/Integration.Tests/LockScreenSafetyTests.cs`

**Interfaces:**
- Produces: `SectorMessageReader.Read(string imagePath) -> SectorDisplayModel`; `ScenarioViewModel` exposing message, scenario ID, status, and display-only countdown.

- [ ] **Step 1: Write failing tests** for sector-message parsing, malformed-sector rejection, countdown completion with no callback, administrative close command, and absence of shell/policy/startup/task-manager modification APIs.
- [ ] **Step 2: Run** the integration tests; expect failure.
- [ ] **Step 3: Implement the read-only parser, view model, and full-screen WPF presentation with normal close/Alt+F4 and a visible laboratory banner.**
- [ ] **Step 4: Run** the tests and manually verify closure in a Windows VM.
- [ ] **Step 5: Commit** `feat: add non-blocking forensic lock-screen fixture`.

## Task 12: End-to-end handlers, collection, and recovery

**Files:**
- Modify: `src/WindowsLabAgent/OperationDispatcher.cs`, `AgentHost.cs`, `Program.cs`
- Create: `src/WindowsLabAgent/Handlers/*.cs`, `src/WindowsLabAgent/ArtifactCollector.cs`
- Create: `tests/Integration.Tests/ScenarioExecutionTests.cs`, `tests/Integration.Tests/RecoveryIntegrationTests.cs`

**Interfaces:**
- Consumes: all artifact-module interfaces from Tasks 6–11.
- Produces: complete scenario artifacts and process exit codes `0` success, `10` validation rejection, `20` safety rejection, `30` operation failure, `40` aborted-and-collected.

- [ ] **Step 1: Write a failing end-to-end test** that signs a bounded scenario, runs the agent in a temporary directory, and asserts sector image, encrypted virtual volume, escrow, offline PCAPNG, JSONL chain, ETW emission attempt, hash manifest, diff report, and timeline output.
- [ ] **Step 2: Write failing recovery and boundary tests** for byte-perfect restore, expired/replayed manifest rejection before mutation, cancellation collection, tampered escrow, forbidden paths, excessive limits, and missing local confirmation.
- [ ] **Step 3: Run** `dotnet test tests/Integration.Tests/Integration.Tests.csproj`; expect failure.
- [ ] **Step 4: Implement fixed operation handlers, collector, hash manifest, timeline builder, confirmation gate, error mapping, and dependency composition in `Program.cs`.**
- [ ] **Step 5: Run** `dotnet test NotPetyaForensicLab.sln --configuration Release`; expect all tests pass or documented Windows-only skips on non-Windows hosts.
- [ ] **Step 6: Run** `dotnet build NotPetyaForensicLab.sln --configuration Release --no-restore`; expect zero warnings and zero errors.
- [ ] **Step 7: Commit** `feat: integrate complete forensic lab scenario`.

## Task 13: Fuzzing, static boundary audit, and operator documentation

**Files:**
- Create: `tests/SafetyInvariants.Tests/BinaryParserFuzzTests.cs`, `ManifestFuzzTests.cs`, `ForbiddenApiTests.cs`
- Create: `README.md`, `docs/VM-LAB-GUIDE.md`, `docs/ARTIFACT-FORMATS.md`, `docs/FORENSIC-ANALYSIS.md`

**Interfaces:**
- Consumes: the complete solution.
- Produces: reproducible build/run/test instructions and a machine-checkable forbidden-API report.

- [ ] **Step 1: Add deterministic fuzz/property tests** for manifest JSON, sector messages, volume headers/directories/journal, PCAPNG lengths, integer boundaries, truncation, random cancellation points, and corrupted authentication metadata.
- [ ] **Step 2: Add compiled-assembly forbidden-API tests** for raw-device paths, networking, remote management, service creation, process launch, PowerShell, registry persistence, shell replacement, and privilege manipulation.
- [ ] **Step 3: Run the full Release suite repeatedly** with randomized seeds recorded on failure; expect no crash, out-of-bounds access, unauthorized I/O, or nondeterministic state corruption.
- [ ] **Step 4: Write operator documentation** covering prerequisites, Visual Studio build, VM snapshot procedure, key generation, manifest signing, scenario execution, artifact collection, restoration, Wireshark/TShark inspection, ETW collection, and failure recovery.
- [ ] **Step 5: Perform a clean-room verification** from a fresh Windows VM using only the README; preserve logs and hashes.
- [ ] **Step 6: Commit** `test: harden parsers and document forensic lab operation`.

## Final verification gate

- [ ] Run `dotnet restore NotPetyaForensicLab.sln`.
- [ ] Run `dotnet build NotPetyaForensicLab.sln -c Release --no-restore`; require zero warnings/errors.
- [ ] Run `dotnet test NotPetyaForensicLab.sln -c Release --no-build`; require all applicable tests pass.
- [ ] Run the forbidden-API safety suite separately and archive its report.
- [ ] Execute one complete scenario in a disposable Windows VM snapshot.
- [ ] Confirm byte-perfect restoration of every virtual file.
- [ ] Confirm Wireshark/TShark opens the PCAPNG and shows the intended staged conversation.
- [ ] Confirm no socket, raw device, mounted volume, host-file transform, persistence, remote-management, or privilege-escalation operation occurred.
- [ ] Compare all generated formats against approved golden artifacts and archive SHA-256 hashes.
