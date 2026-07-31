function OpenAILogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 41 41" aria-hidden="true" className={className}>
      <path
        fill="currentColor"
        d="M37.532 16.871a10.1 10.1 0 0 0-.856-8.185 10.11 10.11 0 0 0-10.855-4.835 10.1 10.1 0 0 0-17.129 3.627 10.11 10.11 0 0 0-5.424 16.651 10.1 10.1 0 0 0 11.711 13.02 10.1 10.1 0 0 0 17.133-3.631 10.11 10.11 0 0 0 5.42-16.647Zm-15.034 21.014a7.48 7.48 0 0 1-4.799-1.735l.237-.134 7.964-4.6a1.31 1.31 0 0 0 .655-1.134V19.054l3.366 1.944.066.092v9.299a7.5 7.5 0 0 1-7.489 7.496ZM6.392 31.006a7.48 7.48 0 0 1-.894-5.023l.237.141 7.964 4.601a1.31 1.31 0 0 0 1.308 0l9.724-5.615v3.888l-.048.103-8.051 4.649a7.5 7.5 0 0 1-10.24-2.744ZM4.297 13.619a7.48 7.48 0 0 1 3.902-3.286l-.004.274v9.201a1.31 1.31 0 0 0 .654 1.132l9.723 5.614-3.366 1.944-.114.01-8.052-4.652a7.5 7.5 0 0 1-2.743-10.237Zm27.658 6.437-9.724-5.615 3.367-1.943.113-.01 8.052 4.648a7.5 7.5 0 0 1-1.158 13.528v-9.476a1.31 1.31 0 0 0-.65-1.132Zm3.351-5.043-.237-.141-7.964-4.601a1.31 1.31 0 0 0-1.309 0l-9.723 5.615v-3.888l.048-.103 8.051-4.645a7.5 7.5 0 0 1 11.134 7.763ZM14.242 21.942l-3.367-1.944-.065-.092v-9.299a7.5 7.5 0 0 1 12.293-5.756l-.236.134-7.965 4.6a1.31 1.31 0 0 0-.654 1.133l-.006 11.224Zm1.829-3.943 4.331-2.501 4.331 2.5v5l-4.331 2.5-4.331-2.5v-4.999Z"
      />
    </svg>
  );
}

function isOpenAIModel(model: string) {
  return /^(?:gpt-|o[134](?:-|$)|codex(?:-|$))/i.test(model);
}

function openAIModelUrl(model: string) {
  return `https://developers.openai.com/api/docs/models/${encodeURIComponent(model)}`;
}

function formatEffort(effort: string | number) {
  if (typeof effort === "number") return String(effort);
  return effort.charAt(0).toUpperCase() + effort.slice(1);
}

export function RunConfiguration({ model, reasoningEffort }: { model?: string | null; reasoningEffort?: string | number | null }) {
  const hasReasoningEffort = reasoningEffort !== undefined && reasoningEffort !== null;
  if (!model && !hasReasoningEffort) return null;

  return (
    <span className="inline-flex w-full items-center justify-end gap-2 text-faint">
      {model && isOpenAIModel(model) ? (
        <a href={openAIModelUrl(model)} target="_blank" rel="noreferrer" className="pointer-events-auto inline-flex min-w-0 items-center gap-1.5 text-inherit no-underline hover:text-ink" title={`View OpenAI model page: ${model}`}>
          <OpenAILogo className="size-3.5 shrink-0" />
          <span className="truncate">{model}</span>
        </a>
      ) : model ? (
        <span className="min-w-0 truncate" title={`Model: ${model}`}>{model}</span>
      ) : null}
      {hasReasoningEffort ? (
        <span className="shrink-0" aria-label={`Reasoning effort: ${reasoningEffort}`} title={`Reasoning effort: ${reasoningEffort}`}>{formatEffort(reasoningEffort)}</span>
      ) : null}
    </span>
  );
}
