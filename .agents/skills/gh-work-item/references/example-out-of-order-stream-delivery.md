# Example Issue: Out-Of-Order Stream Delivery

Title: `streams: implement opt-in out-of-order receive delivery`

Labels: `feature`, `protocol`, `needs-design`

```markdown
## Summary

Implement an opt-in receive mode that can deliver stream data ranges to applications before earlier gaps on the same stream have been filled.

## Background

RFC 9000 section 2.2 permits implementations to offer out-of-order stream data delivery. This came up while reviewing unimplemented RFC 9000 MAY items for protocol feature tracking.

## RFC / Spec Reference

RFC 9000 section 2.2: "However, implementations MAY choose to offer the ability to deliver data out of order to a receiving application."

## Current Behavior

CoQUIC buffers received stream data and emits receive effects only when the data is contiguous for the application. Applications do not receive offsets for sparse stream ranges and cannot consume later ranges before earlier ranges arrive.

## Desired Outcome

Expose an opt-in API/configuration path that reports received stream ranges with offsets while preserving the current contiguous-delivery behavior as the default.

## Scope

- Add an API/configuration switch for out-of-order receive delivery.
- Define receive effects that include stream ID, offset, bytes, and FIN/final-size state.
- Preserve existing contiguous stream delivery semantics by default.
- Handle duplicate ranges, overlapping ranges, stream reset, final-size conflicts, and flow-control accounting.
- Add tests for gaps, duplicates, FIN, reset, and mixed contiguous/out-of-order delivery.

## Acceptance Criteria

- [ ] Existing stream receive behavior remains unchanged unless the new mode is enabled.
- [ ] In opt-in mode, applications can receive later stream ranges before earlier gaps are filled.
- [ ] Receive events include enough metadata to reconstruct stream order.
- [ ] Duplicate and overlapping ranges do not produce incorrect application-visible data.
- [ ] FIN and final-size handling remain compliant with existing stream-state rules.
- [ ] Flow-control credit is updated consistently with consumed or delivered data semantics.

## Validation

- [ ] `nix develop -c zig build test`
- [ ] `nix develop -c ./scripts/compliance`
- [ ] Stream receive tests cover gaps, duplicates, overlaps, FIN, reset, and final-size conflicts.
- [ ] FFI/API tests cover the new receive effect shape if exposed publicly.

## Tracking

- Source: RFC 9000 section 2.2 optional-feature review for QUIC stream receive support.
- Related: none known

---

Created by Codex (GPT-5).
```
