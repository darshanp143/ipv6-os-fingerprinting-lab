import argparse, json
from pathlib import Path
from scapy.all import rdpcap, IPv6, ICMPv6EchoReply

from .fingerprint import classify_reply

def analyze(path):
    packets = rdpcap(str(path))
    replies = []
    for i, pkt in enumerate(packets):
        if IPv6 in pkt and ICMPv6EchoReply in pkt:
            ip = pkt[IPv6]
            fp = classify_reply(int(ip.tc), int(ip.hlim), int(ip.fl))
            replies.append({
                "packet_index": i,
                "src": ip.src,
                "dst": ip.dst,
                "traffic_class": int(ip.tc),
                "hop_limit": int(ip.hlim),
                "flow_label": int(ip.fl),
                "fingerprint": fp.os_guess,
                "confidence": fp.confidence,
                "evidence": fp.evidence,
            })

    return {
        "pcap": str(path),
        "packet_count": len(packets),
        "echo_reply_count": len(replies),
        "replies": replies,
    }

def main():
    ap = argparse.ArgumentParser(description="Analyze IPv6 PCAPs for OS-like fingerprints.")
    ap.add_argument("pcap")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    result = analyze(args.pcap)
    print(json.dumps(result, indent=2))

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Saved report: {args.json}")

if __name__ == "__main__":
    main()
