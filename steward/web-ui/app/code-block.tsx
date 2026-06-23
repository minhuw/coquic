"use client";

import { Check, Copy } from "lucide-react";
import { type CSSProperties, useEffect, useMemo, useState } from "react";
import type { HighlighterCore, LanguageRegistration, ThemedToken, ThemeRegistrationRaw } from "shiki";

type HighlightLanguage =
  | "bash"
  | "css"
  | "diff"
  | "javascript"
  | "json"
  | "markdown"
  | "python"
  | "tsx"
  | "typescript"
  | "yaml"
  | "zig";

type CodeToken = Pick<ThemedToken, "content" | "color" | "fontStyle">;
type DiffCell = { kind: "added" | "context" | "empty" | "removed"; lineNumber: string; text: string };
type DiffMetaVariant = "file" | "hunk" | "plain";
type DiffSplitRow =
  | { kind: "content"; oldCell: DiffCell; newCell: DiffCell }
  | { kind: "meta"; text: string; variant: DiffMetaVariant };

type CodeBlockProps = {
  className?: string;
  compact?: boolean;
  language?: string;
  showLineNumbers?: boolean;
  text: string;
  title?: string;
};

const CODE_THEME = "github-light";
const TOKENIZE_MAX_LINE_LENGTH = 3000;
const TOKENIZE_TIME_LIMIT_MS = 250;

let highlighterPromise: Promise<HighlighterCore> | null = null;

export function CodeBlock({
  className = "",
  compact = false,
  language,
  showLineNumbers = true,
  text,
  title,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const [tokens, setTokens] = useState<{ key: string; tokens: CodeToken[][] } | null>(null);
  const normalizedLanguage = normalizeLanguage(language);
  const highlightKey = `${normalizedLanguage || "text"}\n${text}`;
  const sourceLines = useMemo(() => splitLines(text), [text]);
  const splitDiffRows = useMemo(() => buildSplitDiffRows(sourceLines), [sourceLines]);
  const fallbackTokens = useMemo<CodeToken[][]>(
    () => sourceLines.map((line) => (line ? [{ content: line }] : [])),
    [sourceLines],
  );
  const highlightedTokens = tokens?.key === highlightKey ? tokens.tokens : null;
  const renderedTokens = highlightedTokens ?? fallbackTokens;
  const lineCount = Math.max(sourceLines.length, renderedTokens.length, 1);
  const label = title || languageLabel(normalizedLanguage || language || "text");

  useEffect(() => {
    let cancelled = false;
    if (!normalizedLanguage || normalizedLanguage === "diff") return () => {
      cancelled = true;
    };
    getHighlighter()
      .then((highlighter) => {
        const result = highlighter.codeToTokens(text, {
          lang: normalizedLanguage,
          theme: CODE_THEME,
          tokenizeMaxLineLength: TOKENIZE_MAX_LINE_LENGTH,
          tokenizeTimeLimit: TOKENIZE_TIME_LIMIT_MS,
        });
        if (!cancelled) setTokens({ key: highlightKey, tokens: result.tokens });
      })
      .catch(() => {
        if (!cancelled) setTokens((current) => current?.key === highlightKey ? null : current);
      });
    return () => {
      cancelled = true;
    };
  }, [highlightKey, normalizedLanguage, text]);

  async function copyCode() {
    try {
      if (navigator.clipboard) await navigator.clipboard.writeText(text);
      else copyWithTextarea(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      copyWithTextarea(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    }
  }

  return (
    <div className={`code-block ${compact ? "compact" : ""} ${className}`.trim()}>
      <div className="code-block-toolbar">
        <span className="code-block-title">{label}</span>
        <button
          aria-label={copied ? "Code copied" : "Copy code"}
          className="code-copy-button"
          onClick={copyCode}
          title={copied ? "Copied" : "Copy code"}
          type="button"
        >
          {copied ? <Check size={14} /> : <Copy size={14} />}
        </button>
      </div>
      {normalizedLanguage === "diff" ? (
        <SplitDiffView rows={splitDiffRows} showLineNumbers={showLineNumbers} />
      ) : (
        <pre className="code-block-pre">
          <code className={`code-block-code ${codeNumberMode(showLineNumbers)}`}>
            {Array.from({ length: lineCount }, (_, index) => {
              const lineTokens = renderedTokens[index] ?? fallbackTokens[index] ?? [];
              return (
                <span className="code-block-line" key={index}>
                  {showLineNumbers && <span className="code-line-number">{index + 1}</span>}
                  <span className="code-line-content">
                    {lineTokens.length ? (
                      lineTokens.map((token, tokenIndex) => (
                        <span className="code-token" key={`${index}-${tokenIndex}`} style={tokenStyle(token)}>
                          {token.content}
                        </span>
                      ))
                    ) : (
                      <span className="code-empty-line"> </span>
                    )}
                  </span>
                </span>
              );
            })}
          </code>
        </pre>
      )}
    </div>
  );
}

function SplitDiffView({ rows, showLineNumbers }: { rows: DiffSplitRow[]; showLineNumbers: boolean }) {
  return (
    <div className="diff-split" role="table" aria-label="Side-by-side diff">
      <div className="diff-split-header" role="row">
        <div className="diff-split-column-label" role="columnheader">
          Old
        </div>
        <div className="diff-split-column-label" role="columnheader">
          New
        </div>
      </div>
      <div className="diff-split-body">
        {rows.map((row, index) =>
          row.kind === "meta" ? (
            <div className={`diff-split-meta ${row.variant}`} key={index} role="row">
              {row.text.split("\n").map((line, lineIndex) => (
                <span key={lineIndex}>{line || " "}</span>
              ))}
            </div>
          ) : (
            <div className="diff-split-row" key={index} role="row">
              <DiffSplitCell cell={row.oldCell} showLineNumbers={showLineNumbers} />
              <DiffSplitCell cell={row.newCell} showLineNumbers={showLineNumbers} />
            </div>
          ),
        )}
      </div>
    </div>
  );
}

function DiffSplitCell({ cell, showLineNumbers }: { cell: DiffCell; showLineNumbers: boolean }) {
  return (
    <div className={`diff-split-cell ${cell.kind}`} role="cell">
      <span className="diff-split-line-number">{showLineNumbers ? cell.lineNumber || " " : " "}</span>
      <span className="diff-split-marker">{diffMarker(cell.kind)}</span>
      <span className="diff-split-content">{cell.text || " "}</span>
    </div>
  );
}

function getHighlighter() {
  highlighterPromise ??= loadHighlighter();
  return highlighterPromise;
}

async function loadHighlighter() {
  const [
    { createHighlighterCore },
    { createJavaScriptRegexEngine },
    githubLight,
    bash,
    css,
    diff,
    javascript,
    json,
    markdown,
    python,
    tsx,
    typescript,
    yaml,
    zig,
  ] = await Promise.all([
    import("shiki/core"),
    import("shiki/engine/javascript"),
    import("shiki/themes/github-light.mjs") as Promise<{ default: ThemeRegistrationRaw }>,
    import("shiki/langs/bash.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/css.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/diff.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/javascript.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/json.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/markdown.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/python.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/tsx.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/typescript.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/yaml.mjs") as Promise<{ default: LanguageRegistration[] }>,
    import("shiki/langs/zig.mjs") as Promise<{ default: LanguageRegistration[] }>,
  ]);
  return createHighlighterCore({
    engine: createJavaScriptRegexEngine(),
    langAlias: {
      js: "javascript",
      md: "markdown",
      patch: "diff",
      py: "python",
      sh: "bash",
      shell: "bash",
      ts: "typescript",
      yml: "yaml",
    },
    langs: [
      ...bash.default,
      ...css.default,
      ...diff.default,
      ...javascript.default,
      ...json.default,
      ...markdown.default,
      ...python.default,
      ...tsx.default,
      ...typescript.default,
      ...yaml.default,
      ...zig.default,
    ],
    themes: [githubLight.default],
  });
}

function normalizeLanguage(value?: string): HighlightLanguage | null {
  const cleaned = (value || "")
    .trim()
    .toLowerCase()
    .replace(/^language-/, "")
    .replace(/^\./, "")
    .split(/\s+/)[0];
  if (!cleaned || ["text", "txt", "plain", "plaintext", "log", "output"].includes(cleaned)) return null;
  if (["bash", "console", "sh", "shell", "shellscript", "zsh"].includes(cleaned)) return "bash";
  if (["diff", "patch"].includes(cleaned)) return "diff";
  if (["js", "jsx", "javascript"].includes(cleaned)) return "javascript";
  if (["json", "jsonc", "jsonl"].includes(cleaned)) return "json";
  if (["md", "markdown"].includes(cleaned)) return "markdown";
  if (["py", "python"].includes(cleaned)) return "python";
  if (["ts", "typescript"].includes(cleaned)) return "typescript";
  if (cleaned === "tsx") return "tsx";
  if (["css", "scss", "sass"].includes(cleaned)) return "css";
  if (["yaml", "yml"].includes(cleaned)) return "yaml";
  if (cleaned === "zig") return "zig";
  return null;
}

function splitLines(text: string) {
  return text.split("\n");
}

function codeNumberMode(showLineNumbers: boolean) {
  if (!showLineNumbers) return "no-line-numbers";
  return "with-line-numbers";
}

function buildSplitDiffRows(lines: string[]): DiffSplitRow[] {
  const rows: DiffSplitRow[] = [];
  let pendingMeta: string[] = [];
  let pendingMetaVariant: DiffMetaVariant = "plain";
  let pendingRemoved: DiffCell[] = [];
  let pendingAdded: DiffCell[] = [];
  let oldLine: number | null = null;
  let newLine: number | null = null;

  function appendMeta(line: string, variant: DiffMetaVariant) {
    if (variant === "file" && line.startsWith("diff --git ") && pendingMeta.length) flushMeta();
    pendingMeta.push(line);
    if (variant === "file") pendingMetaVariant = "file";
  }

  function flushMeta() {
    if (!pendingMeta.length) return;
    rows.push({ kind: "meta", text: pendingMeta.join("\n"), variant: pendingMetaVariant });
    pendingMeta = [];
    pendingMetaVariant = "plain";
  }

  function flushPending() {
    const rowCount = Math.max(pendingRemoved.length, pendingAdded.length);
    for (let index = 0; index < rowCount; index += 1) {
      rows.push({
        kind: "content",
        oldCell: pendingRemoved[index] ?? emptyDiffCell(),
        newCell: pendingAdded[index] ?? emptyDiffCell(),
      });
    }
    pendingRemoved = [];
    pendingAdded = [];
  }

  lines.forEach((line, index) => {
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) {
      flushMeta();
      flushPending();
      oldLine = Number.parseInt(hunk[1], 10);
      newLine = Number.parseInt(hunk[2], 10);
      rows.push({ kind: "meta", text: line, variant: "hunk" });
      return;
    }
    if (isDiffFileHeader(line) || line.startsWith("diff --git ") || line.startsWith("index ") || line.startsWith("\\")) {
      flushPending();
      appendMeta(line, isDiffFileHeader(line) || line.startsWith("diff --git ") ? "file" : "plain");
      return;
    }
    if (line === "" && index === lines.length - 1) {
      flushMeta();
      flushPending();
      return;
    }
    if (oldLine === null || newLine === null) {
      flushPending();
      appendMeta(line, "plain");
      return;
    }
    if (line.startsWith("+") && !line.startsWith("+++")) {
      flushMeta();
      pendingAdded.push({ kind: "added", lineNumber: String(newLine), text: line.slice(1) });
      newLine += 1;
      return;
    }
    if (line.startsWith("-") && !line.startsWith("---")) {
      flushMeta();
      if (pendingAdded.length) flushPending();
      pendingRemoved.push({ kind: "removed", lineNumber: String(oldLine), text: line.slice(1) });
      oldLine += 1;
      return;
    }
    flushMeta();
    flushPending();
    const text = line.startsWith(" ") ? line.slice(1) : line;
    rows.push({
      kind: "content",
      oldCell: { kind: "context", lineNumber: String(oldLine), text },
      newCell: { kind: "context", lineNumber: String(newLine), text },
    });
    oldLine += 1;
    newLine += 1;
  });
  flushMeta();
  flushPending();
  return rows;
}

function isDiffFileHeader(line: string) {
  return line.startsWith("--- ") || line.startsWith("+++ ");
}

function emptyDiffCell(): DiffCell {
  return { kind: "empty", lineNumber: "", text: "" };
}

function diffMarker(kind: DiffCell["kind"]) {
  if (kind === "added") return "+";
  if (kind === "removed") return "-";
  return " ";
}

function tokenStyle(token: CodeToken): CSSProperties {
  const style: CSSProperties = {};
  if (token.color) style.color = token.color;
  const fontStyle = token.fontStyle ?? 0;
  if (fontStyle & 1) style.fontStyle = "italic";
  if (fontStyle & 2) style.fontWeight = 700;
  if (fontStyle & 4) style.textDecoration = "underline";
  return style;
}

function languageLabel(value: string) {
  const normalized = normalizeLanguage(value);
  if (!normalized) return "Plain text";
  if (normalized === "tsx") return "TSX";
  return normalized.toUpperCase();
}

function copyWithTextarea(text: string) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}
