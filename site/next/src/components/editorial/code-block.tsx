import { codeToTokens } from 'shiki';
import type { BundledLanguage } from 'shiki';

import { CopyCodeButton } from '@/components/docs/copy-code-button';
import { ScrollRegion } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

import { CodeBlockFrame } from './code-block-frame';
export { CodeBlockFrame } from './code-block-frame';
export type { CodeBlockFrameProps } from './code-block-frame';
import styles from './code-block.module.css';

export type CodeBlockProps = {
  code: string;
  className?: string;
  language?: string;
  variant?: 'compact' | 'default';
};

export async function CodeBlock({ className, code, language = '', variant = 'default' }: CodeBlockProps) {
  const { tokens } = await codeToTokens(code, {
    lang: normalizeLanguage(language),
    themes: {
      light: 'github-light',
      dark: 'github-dark',
    },
    defaultColor: false,
  });
  const displayLanguage = language || 'text';

  return (
    <CodeBlockFrame
      className={className}
      language={displayLanguage}
      toolbar={<CopyCodeButton code={code} />}
      variant={variant}
    >
      <ScrollRegion
        aria-label={`${displayLanguage} code`}
        axis="horizontal"
        className={cn(styles.scroll, 'editorial-code-scroll')}
      >
        <pre className={styles.pre}>
          <code data-language={displayLanguage}>
            {tokens.map((line, lineIndex) => (
              <span className={cn(styles.line, 'editorial-code-line')} key={lineIndex}>
                {line.map((token, tokenIndex) => (
                  <span key={tokenIndex} style={token.htmlStyle ?? { color: token.color }}>
                    {token.content}
                  </span>
                ))}
                {lineIndex < tokens.length - 1 ? '\n' : null}
              </span>
            ))}
          </code>
        </pre>
      </ScrollRegion>
    </CodeBlockFrame>
  );
}


export type HighlightLanguage = BundledLanguage | 'text';

export function normalizeLanguage(language: string): HighlightLanguage {
  if (!language) return 'text';
  if (language === 'sh') return 'bash';
  if (language === 'c++') return 'cpp';
  if (isBundledLanguage(language)) return language;
  return 'text';
}

function isBundledLanguage(language: string): language is BundledLanguage {
  return ['bash', 'c', 'cpp', 'css', 'html', 'javascript', 'json', 'markdown', 'rust', 'typescript', 'zig'].includes(
    language,
  );
}
