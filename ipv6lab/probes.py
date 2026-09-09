from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, Raw

LAB_PREFIX = "fd00:db8:1::"

def echo_probe(dst, tc=0, hlim=64, fl=0):
    return IPv6(dst=dst, tc=tc, hlim=hlim, fl=fl) / ICMPv6EchoRequest()

def extension_chain_probe(dst, count=20, include_hbh=False):
    pkt = IPv6(dst=dst, hlim=64)
    if include_hbh:
        pkt /= IPv6ExtHdrHopByHop(options=[])
    for _ in range(count):
        pkt /= IPv6ExtHdrDestOpt(options=[])
    return pkt / ICMPv6EchoRequest()

def malformed_unknown_next_header(dst, next_header=254):
    # Build an IPv6 packet whose Next Header is an unassigned/experimental
    # value. This builder is for an isolated lab and is not transmitted here.
    return IPv6(dst=dst, nh=next_header) / Raw(b"LAB")

def build_demo_suite(dst):
    return {
        "echo_default": echo_probe(dst),
        "echo_tc_ff": echo_probe(dst, tc=0xFF),
        "ext_chain_20": extension_chain_probe(dst, count=20),
        "ext_chain_30_hbh": extension_chain_probe(dst, count=30, include_hbh=True),
        "unknown_nh_254": malformed_unknown_next_header(dst, 254),
    }
