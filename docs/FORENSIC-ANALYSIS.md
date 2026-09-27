# Forensic analysis workflow

1. Compute SHA-256 for every artifact before opening it.
2. Compare `disk.img` against the offset table and generate a sector-level hexadecimal diff.
3. Inspect `volume.img` entropy by aligned block. Use the virtual directory and journal to correlate transformed blocks.
4. Validate that ciphertext or tag modification makes AES-GCM restoration fail.
5. Open `trace.pcapng` in Wireshark/TShark and filter with `tcp.port == 445`. Confirm every source/destination belongs to an RFC 5737 documentation range. Expect valid lower layers and SMB2 headers; the command bodies are explicit inert markers, not replayable SMB/DCE-RPC messages.
6. Validate the JSONL chain from sequence one and correlate it with ETW provider `ForensicLab-Agent`.
7. Confirm no raw-device, socket, remote-management, service-control, persistence, or host-file transformation event occurred.
8. Restore the virtual files and compare their SHA-256 values to the directory's original hashes.

Recommended collection commands:

```powershell
Get-FileHash C:\ForensicLab\*.img,C:\ForensicLab\*.pcapng,C:\ForensicLab\*.json* -Algorithm SHA256
tshark -r C:\ForensicLab\trace.pcapng -V > C:\ForensicLab\trace-decoded.txt
```
