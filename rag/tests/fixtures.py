from __future__ import annotations

from pathlib import Path


RFC9000_FIXTURE_TEXT = """Network Working Group
Request for Comments: 9000

QUIC: A UDP-Based Multiplexed and Secure Transport

Abstract

This is a compact RFC fixture for RAG tests.

4.1.  Sending Data

This section discusses packet scheduling without naming acknowledgment frames.

5.2.3.  Preferred Address

See Section 21.11 for deployment considerations.

7.4.1.  Transport Parameter Processing

Endpoints validate max_udp_payload_size during transport parameter processing.

13.2.  Generating Acknowledgments

Endpoints send acknowledgments for received packets.

13.4.2.  ECN Counts

See Appendix A.4 for an example.

13.4.2.1.  ECN Validation

Receivers can use an ACK frame when validating ECN counts. See Section 13.2.

18.2.  Transport Parameter Definitions

max_udp_payload_size (0x03):
The max_udp_payload_size transport parameter is defined.

19.3.  ACK Frames

An ACK frame contains acknowledgment ranges and ACK delay information.

20.1.  Transport Error Codes

FRAME_ENCODING_ERROR (0x07):
A frame was malformed.

CRYPTO_ERROR (0x0100-0x01ff):
The cryptographic handshake failed.

21.11.  Additional Security Considerations

Deployments account for preferred address validation.

A.4.  Sample Loss Detection

This appendix describes loss detection examples.
"""


RFC9369_FIXTURE_TEXT = """Network Working Group
Request for Comments: 9369

QUIC Version 2

Abstract

This is a compact RFC fixture for RAG tests.

4.  Packet Protection Updates

ACK behavior and frame processing are described for version negotiation.

4.1.  Header Protection Updates

ACK frame behavior is coordinated with transport parameter changes.

5.  Transport Parameter Updates

ACK frequency behavior interacts with transport parameter negotiation.
"""


DRAFT_QLOG_FIXTURE_TEXT = """Network Working Group
Internet-Draft
Intended status: Informational
Expires: 4 April 2027

draft-ietf-quic-qlog-main-schema-13

qlog: Structured Logging for Network Protocols

Abstract

This is a minimal draft fixture for RAG tests.

1.  Introduction

This section describes structured logging for network protocol analysis.
"""


def write_rfc9000_fixture(path: Path) -> Path:
    path.write_text(RFC9000_FIXTURE_TEXT, encoding="utf-8")
    return path


def write_rfc9369_fixture(path: Path) -> Path:
    path.write_text(RFC9369_FIXTURE_TEXT, encoding="utf-8")
    return path


def write_draft_qlog_fixture(path: Path) -> Path:
    path.write_text(DRAFT_QLOG_FIXTURE_TEXT, encoding="utf-8")
    return path


def write_query_fixtures(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    write_rfc9000_fixture(source_dir / "rfc9000.txt")
    write_rfc9369_fixture(source_dir / "rfc9369.txt")
    write_draft_qlog_fixture(source_dir / "draft-ietf-quic-qlog-main-schema-13.txt")
