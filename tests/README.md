# Test Scripts

This folder contains the test plan rather than automatic network execution.

For a real lab implementation, create one script per test case and require:
1. an explicit destination IPv6 address,
2. a lab-interface selection,
3. an authorization/lab confirmation,
4. PCAP capture,
5. result recording.

Recommended filenames based on the study:
- icmpv6_echo.py
- icmpv6_invalid.py
- ndp_solicitation.py
- ndp_dad.py
- ndp_redirect.py
- ra_flags.py
- ext_header_ordering.py
- ext_header_unknown.py
- ext_header_chain.py
- flow_label.py
- malformed_version.py
- malformed_payload_length.py
- invalid_checksum.py
- fragmentation_overlap.py
- fragmentation_reassembly.py
