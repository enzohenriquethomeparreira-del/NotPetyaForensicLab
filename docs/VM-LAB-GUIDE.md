# Windows VM laboratory guide

1. Create a disposable Windows VM with no bridged adapter. Prefer a private or disconnected virtual switch.
2. Take a clean snapshot before installing the .NET 8 runtime or copying the build.
3. Run the agent as a standard user. Administrator and `SYSTEM` are deliberately rejected.
4. Create one marked laboratory root and precreate every empty output file as described in the README. Do not put it on a removable, network, reparse, or mounted virtual drive.
5. Generate controller and recovery RSA-2048 keys outside the artifact directory. Back up the recovery key separately.
6. Create and sign a short-lived manifest for the exact VM fingerprint and exact artifact paths.
7. Start Procmon, ETW collection, and any EDR/SIEM forwarding required for the experiment.
8. Run the Release build with `--confirm LAB-ONLY`.
9. Hash and copy the generated artifacts before analysis. Preserve the VM snapshot until recovery validation is complete.
10. Run `RestoreFromEscrow` in the same authorized scenario to validate byte-perfect recovery of virtual files.

The PCAPNG generator never creates a socket. The service and pipe records are non-reusable laboratory markers inside an offline file. The disk module writes only an ordinary `.img` file and has no raw-device API.
