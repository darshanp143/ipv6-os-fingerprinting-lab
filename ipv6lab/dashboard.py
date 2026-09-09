import streamlit as st
from pathlib import Path
from scapy.all import IPv6, ICMPv6EchoReply, rdpcap
from ipv6lab.fingerprint import classify_reply

st.set_page_config(
    page_title="IPv6 OS Fingerprinting Lab",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 IPv6 OS Fingerprinting Lab")
st.caption("Passive IPv6 operating-system fingerprinting from PCAP traffic")

PROFILES = {
    "Windows-like": {"tc": 0, "hlim": 128, "fl": 0},
    "Linux-like": {"tc": 255, "hlim": 64, "fl": 0x32674},
    "macOS-like": {"tc": 255, "hlim": 64, "fl": 0},
    "BSD-like": {"tc": 0, "hlim": 64, "fl": 0},
}


def analyze_pcap(path):
    packets = rdpcap(str(path))
    replies = []

    for index, packet in enumerate(packets):
        if IPv6 in packet and ICMPv6EchoReply in packet:
            ip = packet[IPv6]

            result = classify_reply(
                int(ip.tc),
                int(ip.hlim),
                int(ip.fl),
            )

            replies.append({
                "packet_index": index,
                "src": ip.src,
                "dst": ip.dst,
                "traffic_class": int(ip.tc),
                "hop_limit": int(ip.hlim),
                "flow_label": int(ip.fl),
                "fingerprint": result.os_guess, 
                "confidence": result.confidence,
                "evidence": result.evidence,
            })

    return len(packets), replies


st.sidebar.header("PCAP Analysis")

demo_files = sorted(Path("pcaps").glob("*.pcap"))

options = ["Select a demo PCAP"] + demo_files

selected = st.sidebar.selectbox(
    "Choose capture",
    options,
    format_func=lambda x: x if isinstance(x, str) else x.name,
)

uploaded = st.sidebar.file_uploader(
    "Or upload a PCAP",
    type=["pcap", "pcapng"],
)

path = None

if uploaded is not None:
    temp_path = Path("uploaded_capture.pcap")
    temp_path.write_bytes(uploaded.getvalue())
    path = temp_path
elif isinstance(selected, Path):
    path = selected

if path is None:
    st.info("Select a demo PCAP or upload an IPv6 PCAP to begin.")
    st.stop()

try:
    packet_count, replies = analyze_pcap(path)
except Exception as error:
    st.error(f"Analysis failed: {error}")
    st.stop()

st.subheader("Capture Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Packets", packet_count)
c2.metric("Echo Replies", len(replies))

if replies:
    detected = replies[0]

    c3.metric(
        "Detected OS",
        detected["fingerprint"].replace("-like", ""),
    )

    c4.metric(
        "Confidence",
        detected["confidence"],
    )
else:
    c3.metric("Detected OS", "Unknown")
    c4.metric("Confidence", "N/A")

if not replies:
    st.warning(
        "No ICMPv6 Echo Replies were found in this capture."
    )
    st.stop()

detected = replies[0]

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("🔎 Fingerprint Evidence")

    st.write(
        f"### {detected['fingerprint']}"
    )

    st.write(
        f"**Confidence:** {detected['confidence']}"
    )

    for evidence in detected["evidence"]:
        st.write("•", evidence)

with right:
    st.subheader("IPv6 Header Values")

    st.metric(
        "Traffic Class",
        f"0x{detected['traffic_class']:02x}",
    )

    st.metric(
        "Hop Limit",
        detected["hop_limit"],
    )

    st.metric(
        "Flow Label",
        f"0x{detected['flow_label']:05x}",
    )

st.divider()

st.subheader("📊 OS Fingerprint Comparison")

comparison = []

for name, profile in PROFILES.items():
    comparison.append({
        "OS Profile": name,
        "Traffic Class": f"0x{profile['tc']:02x}",
        "Hop Limit": profile["hlim"],
        "Flow Label": f"0x{profile['fl']:05x}",
    })

st.dataframe(
    comparison,
    use_container_width=True,
    hide_index=True,
)

st.divider()

st.subheader("🛡️ Security Interpretation")

st.info(
    "IPv6 implementation characteristics can provide useful "
    "passive fingerprinting evidence. This lab examines "
    "Traffic Class, Hop Limit, and Flow Label values from "
    "ICMPv6 Echo Replies."
)

st.write(
    "The current demonstration captures are synthetic PCAPs "
    "created to validate the analysis pipeline. They are not "
    "real captures from live operating systems."
)

with st.expander("View all detected Echo Replies"):
    st.json(replies)

st.caption(
    "Safety: this dashboard performs offline PCAP analysis only. "
    "It does not transmit packets."
)
