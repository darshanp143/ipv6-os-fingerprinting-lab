# IPv6 OS Fingerprinting & RFC Behavior Lab

An educational, isolated-lab project inspired by the supplied SANS paper
**“Investigating Operating System Variations in IPv6 Implementations”**.

## Goal

Generate controlled IPv6 test traffic, save it as PCAP files, analyze replies,
and compare observable behavior with fingerprints for Windows, Linux, macOS,
and BSD.

The source study used an isolated VMware IPv6 lab, Scapy-generated traffic,
PCAP capture, and four OS families. It tested supporting protocol behavior,
core IPv6 mechanics, and malformed-packet handling.

## Safety

Run this project only against systems you own or are explicitly authorized
to test. Keep the lab isolated. The default examples use documentation/ULA
style addresses and the scripts are designed for controlled research.

## Project layout

- `ipv6lab/probes.py` - safe packet builders; no packets are transmitted
- `ipv6lab/fingerprint.py` - passive/PCAP fingerprinting logic
- `ipv6lab/analyze.py` - PCAP analyzer and JSON report writer
- `ipv6lab/generate_pcaps.py` - creates offline demonstration PCAPs
- `tests/` - individual RFC-oriented probe definitions
- `reports/` - generated analysis reports
- `pcaps/` - generated/captured PCAPs

## Setup on Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

## Generate demonstration PCAPs

These are offline files; nothing is sent to a network:

```powershell
python -m ipv6lab.generate_pcaps
```

## Analyze a PCAP

```powershell
python -m ipv6lab.analyze pcaps/demo_linux.pcap --json reports/linux.json
```

## What the fingerprinting demo looks for

The source paper reports that an Echo Reply with a non-zero flow label was
unique to Linux in its test set. It also reported a useful combination of
Traffic Class, Hop Limit, and Flow Label values:

- Windows: `tc=0`, `hlim=128`, `flow_label=0`
- Linux: `tc=0xFF`, non-zero flow label
- macOS: `tc=0xFF`, flow label `0`
- BSD: `tc=0`, flow label `0`, `hlim=64`

These are observations from the supplied study, not universal guarantees for
all versions/configurations.

## Extending the project

The study also examined:
- ICMPv6 Echo and malformed ICMPv6 messages
- Neighbor Solicitation / Neighbor Advertisement
- Duplicate Address Detection
- Router Advertisements
- Extension-header ordering
- Unknown Next Header values
- Extension-header chain length
- Flow-label behavior
- Invalid version/payload length/checksum
- Fragment overlap and reassembly behavior

Add new probe builders under `tests/`, capture traffic in the isolated lab,
and feed the resulting PCAPs into `ipv6lab.analyze`.

## Expected academic deliverables

1. Project source code
2. Test-plan table
3. PCAP evidence
4. JSON/CSV result summaries
5. OS fingerprint comparison
6. Security-impact discussion
7. Screenshots from Wireshark
8. Final report/presentation

## Important limitation

The supplied paper describes observed results from Windows 11, Fedora 43,
macOS Tahoe, and FreeBSD 15.0. This project reproduces the methodology and
fingerprinting concepts; it does not claim that a generated demo PCAP is an
actual capture from those operating systems.
