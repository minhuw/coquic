export function resolveArchiveSelection<T>(requestedId: string | null, fallbackId: string | undefined, lookup: (id: string) => T | null) {
  const requested = requestedId ? lookup(requestedId) : null;
  return requested ?? (fallbackId ? lookup(fallbackId) : null);
}
