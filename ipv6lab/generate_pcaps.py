from pathlib import Path
from scapy.all import IPv6, ICMPv6EchoReply, wrpcap

OUT = Path("pcaps")
OUT.mkdir(exist_ok=True)

# Synthetic PCAPs used only to validate the analyzer.
# They are not captures from real operating systems.
profiles = {
    "demo_windows": {"tc": 0, "hlim": 128, "fl": 0},
    "demo_linux": {"tc": 0xFF, "hlim": 64, "fl": 0x32674},
    "demo_macos": {"tc": 0xFF, "hlim": 64, "fl": 0},
    "demo_bsd": {"tc": 0, "hlim": 64, "fl": 0},
}

for name, p in profiles.items():
    pkt = (
        IPv6(
            src="fd00:db8:1::10",
            dst="fd00:db8:1::1",
            tc=p["tc"],
            hlim=p["hlim"],
            fl=p["fl"],
        )
        / ICMPv6EchoReply()
    )
    wrpcap(str(OUT / f"{name}.pcap"), [pkt])
    print(f"Created {OUT / (name + '.pcap')}")

print("Synthetic PCAP generation complete.")
