# NotPetya Forensic Lab Simulator

A safety-locked Windows forensic simulator for generating disk-image, virtual-volume, offline-PCAPNG, ETW, JSONL, and UI artifacts. It does **not** exploit SMB, authenticate to remote systems, open raw disks, encrypt NTFS files, create services, persist, or transmit packets.

## Requirements

- Windows 10/11 or Windows Server VM
- Visual Studio 2022 17.8+ with the .NET desktop development workload
- .NET 8 SDK
- Standard-user token; the agent rejects Administrator and `SYSTEM`
- Disposable VM snapshot

## Build and test

```powershell
dotnet restore .\NotPetyaForensicLab.sln
dotnet build .\NotPetyaForensicLab.sln -c Release --no-restore
dotnet test .\NotPetyaForensicLab.sln -c Release --no-build
```

## Laboratory root

Create a dedicated directory and marker. Every generated artifact and nonce record must remain beneath it.

```powershell
$LabRoot = 'C:\ForensicLab'
New-Item -ItemType Directory -Force $LabRoot | Out-Null
Set-Content -NoNewline -Path "$LabRoot\.forensic-lab-root" -Value 'FORENSIC-LAB-V1'
$PreparedFiles = 'disk.img','volume.img','trace.pcapng','events.jsonl','escrow.json','timeline.json','nonce-store.jsonl'
$PreparedFiles | ForEach-Object { New-Item -ItemType File -Force "$LabRoot\$_" | Out-Null }
```

The agent rejects UNC paths, Windows device paths, reparse points, junctions, removable drives, relative paths, and unmarked roots. Outputs must be precreated, empty regular files. This lets the agent acquire and validate their handles before performing any write; it never creates an artifact through a mutable pathname.

## Keys and signed manifest

Generate two distinct RSA-2048 key pairs:

- controller key: signs the canonical scenario manifest; the agent receives only its public key;
- recovery key: unwraps per-file AES keys; the private PEM remains external to generated artifacts.

The manifest schema and exact safety claims are documented in `docs/ARTIFACT-FORMATS.md`. Its `controllerThumbprint` is uppercase SHA-256 of the DER SubjectPublicKeyInfo. Sign canonical JSON with RSA-PSS/SHA-256.

## Run

```powershell
.\src\WindowsLabAgent\bin\Release\net8.0-windows\WindowsLabAgent.exe `
  --manifest C:\ForensicLab\scenario.json `
  --signature C:\ForensicLab\scenario.sig `
  --public-key C:\LabKeys\controller-public.pem `
  --recovery-key C:\LabKeys\recovery-private.pem `
  --nonce-store C:\ForensicLab\nonce-store.jsonl `
  --fingerprint LAB-VM-01 `
  --confirm LAB-ONLY
```

To display the optional viewer after sector generation:

```powershell
.\src\LockScreenSimulator\bin\Release\net8.0-windows\LockScreenSimulator.exe C:\ForensicLab\disk.img
```

The viewer is closable with its button or Alt+F4 and has no destructive callback.

## Outputs

- `disk.img`: 512-byte synthetic sector-zero fixture.
- `volume.img`: custom virtual volume containing only generated fixtures.
- `trace.pcapng`: file-only synthetic TCP/SMB-shaped conversation using RFC 5737 addresses.
- `events.jsonl`: hash-chained portable event log.
- `escrow.json`: public recovery-key metadata; never contains a private key.
- `timeline.json`: artifact inventory.

See `docs/VM-LAB-GUIDE.md`, `docs/ARTIFACT-FORMATS.md`, and `docs/FORENSIC-ANALYSIS.md`.
