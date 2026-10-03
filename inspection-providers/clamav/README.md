# FICC local ClamAV inspection provider

Install the built host first, then this wheel in the same Python environment.
Install an approved ClamAV engine and signatures separately. This package does
not download signatures, contact a scanning service, start clamd or modify files.
The separately distributed ClamAV engine uses its own GPL-2.0 licence.

The owner approves `engine`, `database` and `certificate_directory` paths through
FICC inspection settings. The adapter is qualified with native ClamAV 1.5.4.
The host mounts those assets read-only with one exact input file in a bounded,
network-isolated worker. Configuration also sets file/expanded-byte, file-count,
recursion and scan-time limits. Engine limits, encrypted content and broken format
alerts produce incomplete coverage, never a clean-file promise. Files beyond the
ClamAV 2 GiB engine boundary produce incomplete coverage even when FICC can store
and transfer them. Results retain engine and signature hashes and actual limits.

See [inspection operation](../../docs/inspection.md) and the
[scanner SDK](../../sdk/inspection.md). ClamAV reference:
[clamscan options](https://github.com/Cisco-Talos/clamav/blob/clamav-1.5.4/docs/man/clamscan.1.in).
