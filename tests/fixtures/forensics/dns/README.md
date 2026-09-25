# DNS packet corpus

These deterministic synthetic fixtures are format-valid Ethernet/IPv4 PCAP
captures. They contain no production or user traffic.

`dns_udp_resilience.pcap.hex` contains one malformed compression-loop response
followed by valid A and AAAA responses. It proves packet-level continuation
after a recoverable DNS error.

`dns_tcp_multi_segment.pcap.hex` contains two length-prefixed DNS queries in a
single TCP stream, split across three TCP segments. It proves TCP reassembly,
DNS/TCP framing, message ordering, and duplicate-free extraction. The fixture
also has checked packet geometry: capture lengths, IPv4 lengths, TCP payload
lengths, and sequence increments are asserted before DNS decoding.

Tests decode the checked-in hex into exact bytes, assert the fixture BLAKE3,
and only then pass the temporary on-disk PCAP through the production streaming
reader.
