import { Check, Download, LoaderCircle, Terminal, X } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type {
  AtifArtifactAction,
  AtifDisplayContent,
  AtifDisplayContentValue,
  AtifSafeRecord,
} from "@/lib/steward-archive/atif-view-model";

type MessageBlock =
  | { type: "markdown"; text: string }
  | { type: "tasks"; items: Array<{ checked: boolean; text: string }> }
  | { type: "command"; command: string; state: "running" | "completed"; exitCode: number | null; output: string };

const commandPattern = /^command (in_progress|completed exit=(-?\d+)): (.+)$/;
const taskPattern = /^\s*(?:[-*]\s+)?\[([ xX])\]\s+(.+)$/;

function commandMarker(line: string) {
  const match = commandPattern.exec(line);
  if (!match) return null;
  return {
    command: match[3],
    state: match[1] === "in_progress" ? "running" as const : "completed" as const,
    exitCode: match[2] === undefined ? null : Number(match[2]),
  };
}

function parseMessage(text: string): MessageBlock[] {
  const lines = text.replaceAll("\r\n", "\n").split("\n");
  const blocks: MessageBlock[] = [];
  let markdown: string[] = [];

  function flushMarkdown() {
    const value = markdown.join("\n").trim();
    if (value) blocks.push({ type: "markdown", text: value });
    markdown = [];
  }

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const startsTodo = line.trim().toLowerCase() === "todo list" && taskPattern.test(lines[index + 1] ?? "");
    const task = taskPattern.exec(line);
    if (startsTodo || task) {
      flushMarkdown();
      if (startsTodo) index += 1;
      const items: Array<{ checked: boolean; text: string }> = [];
      for (; index < lines.length; index += 1) {
        const item = taskPattern.exec(lines[index]);
        if (!item) break;
        items.push({ checked: item[1].toLowerCase() === "x", text: item[2] });
      }
      blocks.push({ type: "tasks", items });
      index -= 1;
      continue;
    }

    let command = commandMarker(line);
    if (command) {
      flushMarkdown();
      const completed = commandMarker(lines[index + 1] ?? "");
      if (command.state === "running" && completed?.state === "completed" && completed.command === command.command) {
        command = completed;
        index += 1;
      }
      const output: string[] = [];
      if (command.state === "completed") {
        while (index + 1 < lines.length && !commandMarker(lines[index + 1]) && lines[index + 1].trim().toLowerCase() !== "todo list") {
          output.push(lines[index + 1]);
          index += 1;
        }
      }
      blocks.push({ type: "command", ...command, output: output.join("\n").trimEnd() });
      continue;
    }

    markdown.push(line);
  }
  flushMarkdown();
  return blocks;
}

function markdownHref(href: string | undefined): { href: string; external: boolean } | null {
  if (!href || href.trim() !== href || /[\u0000-\u001f]/.test(href)) return null;
  if (href.startsWith("#")) return { href, external: false };
  if (href.startsWith("/") && !href.startsWith("//")) return { href, external: false };
  try {
    const url = new URL(href);
    if (url.protocol !== "http:" && url.protocol !== "https:" && url.protocol !== "mailto:") return null;
    return { href: url.toString(), external: true };
  } catch {
    return null;
  }
}

function MarkdownBlock({ text }: { text: string }) {
  return (
    <div className="transcript-markdown typeset typeset-answer max-w-3xl text-muted [overflow-wrap:anywhere]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        skipHtml
        components={{
          h1: ({ node: _, ...props }) => <h4 {...props} />,
          h2: ({ node: _, ...props }) => <h5 {...props} />,
          h3: ({ node: _, ...props }) => <h6 {...props} />,
          table: ({ node: _, ...props }) => <div className="typeset-scroll max-w-full overflow-x-auto"><table {...props} /></div>,
          pre: ({ node: _, children }) => <div className="max-w-full overflow-x-auto"><pre data-transcript-code className="max-w-full overflow-x-auto" >{children}</pre></div>,
          a: ({ node: _, href, children, ...props }) => {
            const safe = markdownHref(href);
            if (!safe) return <span data-blocked-link {...props}>{children}</span>;
            return <a {...props} href={safe.href} target={safe.external ? "_blank" : undefined} rel={safe.external ? "noreferrer" : undefined}>{children}</a>;
          },
          img: ({ node: _, alt }) => <span data-blocked-image>{alt || "Image unavailable"}</span>,
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}

function TaskBlock({ items }: { items: Array<{ checked: boolean; text: string }> }) {
  const complete = items.filter((item) => item.checked).length;
  return (
    <section aria-label="Todo" className="max-w-3xl border-y border-line py-4">
      <div className="flex items-baseline justify-between gap-4">
        <h4 className="text-sm font-semibold text-ink">Todo</h4>
        <p className="text-xs text-muted data-text">{complete} / {items.length} complete</p>
      </div>
      <ul className="mt-3 space-y-2">
        {items.map((item, index) => <li key={`${item.text}-${index}`} className="flex items-start gap-3 text-sm leading-6 text-muted"><input type="checkbox" checked={item.checked} readOnly disabled className="mt-1 size-4 shrink-0 accent-positive disabled:opacity-100" /><span className={item.checked ? "text-faint line-through" : "text-ink"}>{item.text}</span></li>)}
      </ul>
    </section>
  );
}

function CommandBlock({ block }: { block: Extract<MessageBlock, { type: "command" }> }) {
  const failed = block.exitCode !== null && block.exitCode !== 0;
  const status = block.state === "running" ? "Running" : failed ? `Exit ${block.exitCode}` : "Exit 0";
  return (
    <details data-transcript-command open={block.state === "running" || failed} className="group border-b border-line">
      <summary className="grid cursor-pointer list-none gap-3 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <span className="flex min-w-0 items-start gap-2 text-xs leading-5 text-ink data-text"><Terminal aria-hidden="true" size={14} className="mt-0.5 shrink-0 text-accent" /><code className="break-all">{block.command}</code></span>
        <span className={`flex items-center gap-1.5 text-xs font-medium data-text ${block.state === "running" ? "text-accent" : failed ? "text-negative" : "text-positive"}`}>
          {block.state === "running" ? <LoaderCircle aria-hidden="true" size={13} /> : failed ? <X aria-hidden="true" size={13} /> : <Check aria-hidden="true" size={13} />}
          {status}
        </span>
      </summary>
      {block.output ? <pre className="max-h-96 max-w-full overflow-auto border-t border-line bg-diff-gutter px-4 py-3 text-xs leading-5 text-ink data-text">{block.output}</pre> : null}
    </details>
  );
}

function GenericBlock({ record }: { record: AtifSafeRecord }) {
  return <pre data-generic-content className="max-w-full overflow-auto border border-line bg-diff-gutter px-4 py-3 text-xs leading-5 text-ink data-text">{JSON.stringify(record, null, 2)}</pre>;
}
function ArtifactReference({ action }: { action: AtifArtifactAction }) {
  if (action.kind === "unavailable") {
    return <span data-artifact-unavailable className="text-xs text-unavailable">Artifact unavailable ({action.reason})</span>;
  }
  if (action.kind === "image") {
    return (
      <figure className="mt-3 max-w-full">
        <div className="flex min-h-24 max-w-full items-center justify-center overflow-hidden border border-line bg-diff-gutter p-2">
          <img src={action.href} alt="Published image evidence" className="max-h-[32rem] max-w-full object-contain" />
        </div>
        <figcaption className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted">
          <span>{action.mediaType}</span>
          <span aria-hidden="true">·</span>
          <a href={action.href} download className="inline-flex items-center gap-1 text-accent no-underline hover:text-ink"><Download aria-hidden="true" size={13} />Download image</a>
        </figcaption>
      </figure>
    );
  }
  return <a href={action.href} download className="inline-flex items-center gap-1 text-sm text-accent no-underline hover:text-ink"><Download aria-hidden="true" size={14} />Download artifact<span className="text-muted">({action.mediaType})</span></a>;
}

function ContentPart({ part }: { part: AtifDisplayContent }) {
  if (part.kind === "text") return part.text === null ? <p className="text-sm text-unavailable">Unavailable</p> : <MarkdownBlock text={part.text} />;
  if (part.kind === "generic") return <GenericBlock record={part.record} />;
  return <ArtifactReference action={part.action} />;
}

export interface TranscriptMessageProps {
  /** Legacy plain text remains supported while normalized content migrates. */
  text?: string | null;
  content?: AtifDisplayContentValue;
  parts?: readonly AtifDisplayContent[];
}

export function TranscriptMessage({ text, content, parts }: TranscriptMessageProps) {
  const typedParts = parts && parts.length > 0 ? parts : (Array.isArray(content) ? content : undefined);
  if (typedParts) {
    return (
      <div className="mt-4 min-w-0 space-y-5">
        {typedParts.length > 0
          ? typedParts.map((part, index) => (
            <ContentPart key={`${part.kind}-${index}`} part={part} />
          ))
          : <p className="text-sm text-unavailable">Unavailable</p>}
      </div>
    );
  }

  const value = text !== undefined ? text : typeof content === "string" ? content : null;
  if (value === null || value === undefined) return <p className="mt-4 text-sm text-unavailable">Unavailable</p>;
  const blocks = parseMessage(value);
  return (
    <div className="mt-4 min-w-0 space-y-5">
      {blocks.length === 0 ? <p className="text-sm text-unavailable">Unavailable</p> : blocks.map((block, index) => {
        if (block.type === "markdown") return <MarkdownBlock key={`markdown-${index}`} text={block.text} />;
        if (block.type === "tasks") return <TaskBlock key={`tasks-${index}`} items={block.items} />;
        return <div key={`command-${index}`} className="max-w-4xl border-t border-line"><CommandBlock block={block} /></div>;
      })}
    </div>
  );
}
