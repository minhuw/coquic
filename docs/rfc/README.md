# QUIC Specification Corpus

This directory stores a local text mirror of the QUIC specifications that are
directly useful for transport, HTTP/3, and qlog work in this repository. The
corpus may contain both published RFCs and tracked Internet-Drafts, and the
local RAG indexes them together by generic document identifier such as
`rfc9000` or `draft-ietf-quic-qlog-main-schema-13`.

- Source selection: `https://quicwg.org/`
- RFC text source: `https://www.rfc-editor.org/rfc/`
- Internet-Draft text source: `https://www.ietf.org/archive/id/`
- Machine-readable index: `docs/rfc/manifest.json`

Included documents:

- `rfc8985.txt` - The RACK-TLP Loss Detection Algorithm for TCP
- `rfc8999.txt` - Version-Independent Properties of QUIC
- `rfc9000.txt` - QUIC: A UDP-Based Multiplexed and Secure Transport
- `rfc9001.txt` - Using TLS to Secure QUIC
- `rfc9002.txt` - QUIC Loss Detection and Congestion Control
- `rfc9114.txt` - HTTP/3
- `rfc9204.txt` - QPACK: Field Compression for HTTP/3
- `rfc9221.txt` - An Unreliable Datagram Extension to QUIC
- `rfc9287.txt` - Greasing the QUIC Bit
- `rfc9308.txt` - Applicability of the QUIC Transport Protocol
- `rfc9312.txt` - Manageability of the QUIC Transport Protocol
- `rfc9368.txt` - Compatible Version Negotiation for QUIC
- `rfc9369.txt` - QUIC Version 2
- `draft-ietf-quic-qlog-main-schema-13.txt` - qlog: Structured Logging for Network Protocols
- `draft-ietf-quic-qlog-quic-events-12.txt` - QUIC event definitions for qlog
- `draft-ietf-quic-qlog-h3-events-12.txt` - HTTP/3 qlog event definitions
