# Test Plan

| ID | Category | Test | Expected measurement |
|---|---|---|---|
| T01 | ICMPv6 | Echo Request | Reply header fingerprint |
| T02 | ICMPv6 | Invalid type/code | Error vs silent drop |
| T03 | NDP | Neighbor Solicitation | NA behavior and link-layer option |
| T04 | NDP | DAD | Defense response |
| T05 | NDP | Redirect | Observable response / routing effect |
| T06 | NDP | Router Advertisement | Observable response / host state |
| T07 | Core | Extension-header ordering | Parameter Problem vs silence |
| T08 | Core | Unknown Next Header | Error vs silent discard |
| T09 | Core | Extension-header chain length | Maximum observed processing depth |
| T10 | Core | Flow Label | Stable/non-zero flow-label behavior |
| T11 | Malformed | Version field | Drop/accept behavior |
| T12 | Malformed | Payload length | Drop/accept behavior |
| T13 | Malformed | Invalid checksum | Drop/accept behavior |
| T14 | Fragmentation | Overlap | Reassembly/drop/error behavior |
| T15 | Fragmentation | Missing middle fragment | Timeout behavior |

The supplied paper grouped tests into supporting protocol behavior, core
protocol mechanics, and malformed packet handling, with PCAPs used as the raw
dataset for qualitative comparison.
