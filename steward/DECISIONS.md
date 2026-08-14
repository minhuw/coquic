# Steward decisions

## Static dispatch and boundary adapters

Steward business methods are invoked through one statically dispatched contract.
Internal publication values are the concrete current types, mappings, and
owner-detached values explicitly accepted by each boundary; method-bearing
lookalikes are not a compatibility surface. Mapping traversal and typed
reflection over data fields remain valid because they do not select executable
business behavior.

Only an unavoidable third-party boundary may use a narrow, named adapter for a
pinned provider shape. Such adapters must fail explicitly rather than discover
serializers or search arbitrary object graphs. Publication conversion preserves
canonical bytes, digests, redaction, mutation detection, limits, and bounded
failure categories while rejecting unsupported values without executing their
methods.

Later architecture plans share ownership of this decision log.
