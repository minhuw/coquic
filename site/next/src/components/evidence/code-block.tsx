'use client';

import { Check, Copy, Maximize2, X } from 'lucide-react';
import { type CSSProperties, useEffect, useMemo, useRef, useState } from 'react';
import type { HighlighterCore, LanguageRegistration, ThemeRegistrationRaw, ThemedTokenWithVariants, TokenStyles } from 'shiki';

import { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ScrollRegion } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

import { buildSplitDiffRows, DiffView } from './diff-view';
import styles from './code-block.module.css';

type HighlightLanguage =
  | 'bash'
  | 'css'
  | 'diff'
  | 'javascript'
  | 'json'
  | 'markdown'
  | 'python'
  | 'tsx'
  | 'typescript'
  | 'yaml'
  | 'zig';

type CodeToken = Pick<ThemedTokenWithVariants, 'content' | 'variants'>;
export type DiffDisplay = 'split' | 'unified' | 'unified-with-split-modal';

export type CodeBlockProps = {
  className?: string;
  compact?: boolean;
  diffDisplay?: DiffDisplay;
  language?: string;
  showLineNumbers?: boolean;
  text: string;
  title?: string;
};

const TOKENIZE_MAX_LINE_LENGTH = 3000;
const TOKENIZE_TIME_LIMIT_MS = 250;

let highlighterPromise: Promise<HighlighterCore> | null = null;
const tokenCache = new Map<string, Promise<CodeToken[][]>>();
let tokenizationCount = 0;

export function getEvidenceTokenizationCount() {
  return tokenizationCount;
}

export function CodeBlock({
  className = '',
  compact = false,
  diffDisplay = 'split',
  language,
  showLineNumbers = true,
  text,
  title,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const [diffOpen, setDiffOpen] = useState(false);
  const [tokens, setTokens] = useState<{ key: string; tokens: CodeToken[][] } | null>(null);
  const diffTriggerRef = useRef<HTMLButtonElement>(null);
  const wasDiffOpenRef = useRef(false);
  const normalizedLanguage = normalizeLanguage(language);
  const highlightKey = normalizedLanguage ? `${normalizedLanguage}\n${text}` : '';
  const sourceLines = useMemo(() => splitLines(text), [text]);
  const splitDiffRows = useMemo(() => buildSplitDiffRows(sourceLines), [sourceLines]);
  const fallbackTokens = useMemo<CodeToken[][]>(
    () => sourceLines.map((line) => (line ? [{ content: line, variants: {} }] : [])),
    [sourceLines],
  );
  const highlightedTokens = tokens?.key === highlightKey ? tokens.tokens : null;
  const renderedTokens = highlightedTokens ?? fallbackTokens;
  const lineCount = Math.max(sourceLines.length, renderedTokens.length, 1);
  const label = title || languageLabel(normalizedLanguage || language || 'text');
  const expandableDiff = normalizedLanguage === 'diff' && diffDisplay === 'unified-with-split-modal';
  const inlineDiffDisplay = diffDisplay === 'split' ? 'split' : 'unified';

  useEffect(() => {
    let cancelled = false;
    if (!normalizedLanguage || normalizedLanguage === 'diff') return () => { cancelled = true; };
    tokenizeCode(text, normalizedLanguage)
      .then((result) => {
        if (!cancelled) setTokens({ key: highlightKey, tokens: result });
      })
      .catch(() => {
        if (!cancelled) setTokens((current) => current?.key === highlightKey ? null : current);
      });
    return () => { cancelled = true; };
  }, [highlightKey, normalizedLanguage, text]);

  useEffect(() => {
    if (!diffOpen && wasDiffOpenRef.current) diffTriggerRef.current?.focus();
    wasDiffOpenRef.current = diffOpen;
  }, [diffOpen]);

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
    <div className={cn(styles.root, compact && styles.compact, 'evidence-code-block', 'code-block', compact && 'evidence-code-block--compact', className)} data-evidence-code-block="true" data-evidence-tokenized={highlightedTokens ? 'true' : 'false'}>
      <div className={cn(styles.toolbar, 'evidence-code-toolbar', 'code-block-toolbar')}>
        <span className={cn(styles.title, 'evidence-code-title', 'code-block-title')}>{label}</span>
        <div className={cn(styles.actions, 'evidence-code-actions', 'code-block-actions')}>
          {expandableDiff ? (
            <Dialog open={diffOpen} onOpenChange={(open) => {
              setDiffOpen(open);
              if (!open) diffTriggerRef.current?.focus();
            }}>
              <DialogTrigger asChild>
                <button
                  aria-label="Open side-by-side diff"
                  className={cn(styles.iconButton, 'evidence-icon-button', 'code-copy-button')}
                  title="Open side-by-side diff"
                  ref={diffTriggerRef}
                  type="button"
                >
                  <Maximize2 size={14} aria-hidden="true" />
                </button>
              </DialogTrigger>
              <DialogContent className={cn(styles.dialog, 'evidence-diff-dialog')} onCloseAutoFocus={(event) => {
                event.preventDefault();
                diffTriggerRef.current?.focus();
              }}>
                <div className={cn(styles.dialogToolbar, 'evidence-diff-dialog__toolbar')}>
                  <DialogTitle>{label} side-by-side</DialogTitle>
                  <DialogClose asChild>
                    <button aria-label="Close side-by-side diff" className={cn(styles.iconButton, 'evidence-icon-button', 'code-copy-button')} title="Close" type="button">
                      <X size={14} aria-hidden="true" />
                    </button>
                  </DialogClose>
                </div>
                <DialogDescription className={cn(styles.visuallyHidden, 'evidence-visually-hidden')}>Inspect the side-by-side diff.</DialogDescription>
                <div className={cn(styles.dialogBody, 'evidence-diff-dialog__body')}>
                  <DiffView className={cn(styles.dialogScroll, 'evidence-diff-scroll--dialog')} display="split" rows={splitDiffRows} showLineNumbers={showLineNumbers} />
                </div>
              </DialogContent>
            </Dialog>
          ) : null}
          <button
            aria-label={copied ? 'Code copied' : 'Copy code'}
            className={cn(styles.iconButton, 'evidence-icon-button', 'code-copy-button')}
            onClick={copyCode}
            title={copied ? 'Copied' : 'Copy code'}
            type="button"
          >
            {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
          </button>
          <span aria-live="polite" className={cn(styles.visuallyHidden, 'evidence-visually-hidden')}>{copied ? 'Code copied' : ''}</span>
        </div>
      </div>
      {normalizedLanguage === 'diff' ? (
        <DiffView display={inlineDiffDisplay} rows={splitDiffRows} showLineNumbers={showLineNumbers} />
      ) : (
        <ScrollRegion aria-label={`${label} code`} axis="both" className={cn(styles.scroll, 'evidence-code-scroll')}>
          <pre className={cn(styles.pre, 'evidence-code-pre', 'code-block-pre')}>
            <code className={cn(styles.code, 'evidence-code-code', 'code-block-code', codeNumberMode(showLineNumbers))}>
              {Array.from({ length: lineCount }, (_, index) => {
                const lineTokens = renderedTokens[index] ?? fallbackTokens[index] ?? [];
                return (
                  <span className={cn(styles.line, 'evidence-code-line', 'code-block-line')} key={index}>
                    {showLineNumbers ? <span className={cn(styles.lineNumber, 'evidence-code-line-number', 'code-line-number')}>{index + 1}</span> : null}
                    <span className={cn(styles.lineContent, 'evidence-code-line-content', 'code-line-content')}>
                      {lineTokens.length ? (
                        lineTokens.map((token, tokenIndex) => (
                          <span className={cn(styles.token, 'evidence-code-token', 'code-token')} data-evidence-token="true" key={`${index}-${tokenIndex}`} style={tokenStyle(token)}>
                            {token.content}
                          </span>
                        ))
                      ) : (
                        <span className={cn(styles.emptyLine, 'evidence-code-empty-line', 'code-empty-line')}> </span>
                      )}
                    </span>
                  </span>
                );
              })}
            </code>
          </pre>
        </ScrollRegion>
      )}
    </div>
  );
}

async function tokenizeCode(text: string, language: HighlightLanguage) {
  const key = `${language}\n${text}`;
  const cached = tokenCache.get(key);
  if (cached) return cached;
  tokenizationCount += 1;
  const promise: Promise<CodeToken[][]> = getHighlighter().then((highlighter) => highlighter.codeToTokensWithThemes(text, {
    lang: language,
    themes: { light: 'github-light', dark: 'github-dark' },
    tokenizeMaxLineLength: TOKENIZE_MAX_LINE_LENGTH,
    tokenizeTimeLimit: TOKENIZE_TIME_LIMIT_MS,
  }));
  tokenCache.set(key, promise);
  promise.catch(() => tokenCache.delete(key));
  return promise;
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
    githubDark,
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
    import('shiki/core'),
    import('shiki/engine/javascript'),
    import('shiki/themes/github-light.mjs') as Promise<{ default: ThemeRegistrationRaw }>,
    import('shiki/themes/github-dark.mjs') as Promise<{ default: ThemeRegistrationRaw }>,
    import('shiki/langs/bash.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/css.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/diff.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/javascript.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/json.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/markdown.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/python.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/tsx.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/typescript.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/yaml.mjs') as Promise<{ default: LanguageRegistration[] }>,
    import('shiki/langs/zig.mjs') as Promise<{ default: LanguageRegistration[] }>,
  ]);
  return createHighlighterCore({
    engine: createJavaScriptRegexEngine(),
    langAlias: {
      js: 'javascript',
      md: 'markdown',
      patch: 'diff',
      py: 'python',
      sh: 'bash',
      shell: 'bash',
      ts: 'typescript',
      yml: 'yaml',
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
    themes: [githubLight.default, githubDark.default],
  });
}

function normalizeLanguage(value?: string): HighlightLanguage | null {
  const cleaned = (value || '')
    .trim()
    .toLowerCase()
    .replace(/^language-/, '')
    .replace(/^\./, '')
    .split(/\s+/)[0];
  if (!cleaned || ['text', 'txt', 'plain', 'plaintext', 'log', 'output'].includes(cleaned)) return null;
  if (['bash', 'console', 'sh', 'shell', 'shellscript', 'zsh'].includes(cleaned)) return 'bash';
  if (['diff', 'patch'].includes(cleaned)) return 'diff';
  if (['js', 'jsx', 'javascript'].includes(cleaned)) return 'javascript';
  if (['json', 'jsonc', 'jsonl'].includes(cleaned)) return 'json';
  if (['md', 'markdown'].includes(cleaned)) return 'markdown';
  if (['py', 'python'].includes(cleaned)) return 'python';
  if (['ts', 'typescript'].includes(cleaned)) return 'typescript';
  if (cleaned === 'tsx') return 'tsx';
  if (['css', 'scss', 'sass'].includes(cleaned)) return 'css';
  if (['yaml', 'yml'].includes(cleaned)) return 'yaml';
  if (cleaned === 'zig') return 'zig';
  return null;
}

function splitLines(text: string) {
  return text.split('\n');
}

function codeNumberMode(showLineNumbers: boolean) {
  return showLineNumbers ? 'with-line-numbers' : 'no-line-numbers';
}

function tokenStyle(token: CodeToken): CSSProperties {
  const light: TokenStyles = token.variants.light ?? {};
  const dark: TokenStyles = token.variants.dark ?? {};
  const style = {} as CSSProperties & Record<string, string | number | undefined>;
  const lightColor = light.color ?? dark.color ?? 'currentColor';
  const darkColor = dark.color ?? light.color ?? 'currentColor';
  style['--shiki-light'] = lightColor;
  style['--shiki-dark'] = darkColor;
  if (light.bgColor || dark.bgColor) {
    style['--shiki-light-bg'] = light.bgColor ?? dark.bgColor;
    style['--shiki-dark-bg'] = dark.bgColor ?? light.bgColor;
  }
  const fontStyle = light.fontStyle ?? dark.fontStyle ?? 0;
  if (fontStyle & 1) style.fontStyle = 'italic';
  if (fontStyle & 2) style.fontWeight = 700;
  if (fontStyle & 4) style.textDecoration = 'underline';
  return style;
}

function languageLabel(value: string) {
  const normalized = normalizeLanguage(value);
  if (!normalized) return 'Plain text';
  if (normalized === 'tsx') return 'TSX';
  return normalized.toUpperCase();
}

function copyWithTextarea(text: string) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', 'true');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}
