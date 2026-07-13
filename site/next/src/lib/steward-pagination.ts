export function paginateStewardItems<T>(items: T[], page: number, pageSize = 10) {
  const safePageSize = Math.max(1, pageSize);
  const pageCount = Math.max(1, Math.ceil(items.length / safePageSize));
  const safePage = Math.max(1, Math.min(page, pageCount));
  const start = (safePage - 1) * safePageSize;
  return {
    page: safePage,
    pageCount,
    pageItems: items.slice(start, start + safePageSize),
    pageSize: safePageSize,
    start,
  };
}
