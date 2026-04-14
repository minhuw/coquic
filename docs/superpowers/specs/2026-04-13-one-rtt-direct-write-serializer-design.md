# One-RTT Direct-Write Serializer Design

## Goal

Reduce send-path allocator churn in 1-RTT packet construction by replacing the
`stream_frame_views` chunked serialization path with direct serialization into
the destination datagram buffer.

## Problem

Post-cache profiling shows the bulk-transfer bottleneck moved from traffic-key
derivation to packet construction. The current `stream_frame_views` path builds
an intermediate header vector plus owned payload chunk vectors and then seals
those chunks. That path creates substantial heap churn in the hot send loop.

## Chosen Approach

Serialize the short header and plaintext payload directly into the final
datagram buffer for packets that carry `stream_frame_views`.

- Keep the existing non-`stream_frame_views` path unchanged.
- Preserve current wire format, frame ordering, rollback behavior, and error
  propagation.
- Validate `StreamFrameView` bounds and varint limits before committing success.
- Seal the final plaintext as one contiguous span with `seal_payload_into`
  instead of `seal_payload_chunks_into`.

## Data Flow

1. Compute the final short header and append it directly to `datagram`.
2. Reserve plaintext space after the packet number field and serialize normal
   `packet.frames` directly into that region.
3. Serialize each `StreamFrameView` header directly into the plaintext region,
   then copy the referenced bytes from shared storage directly behind it.
4. Pad the plaintext region if needed for header-protection sampling.
5. Seal the contiguous plaintext span in place and apply header protection.
6. Roll back `datagram` to its original size on any failure.

## Testing

- Add a focused regression test that proves the `stream_frame_views` send path
  no longer depends on multiple chunked `seal_payload_update` calls.
- Keep the existing append/round-trip/error-path packet tests green.
- Re-run a release bulk benchmark after the change to measure impact.
