'use client';

import { CopyCodeButton } from '@/components/docs/copy-code-button';
import { ScrollRegion } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

import type { CodeBlockProps } from './code-block';
import { CodeBlockFrame } from './code-block-frame';
import styles from './code-block.module.css';

/** Client-safe plain code adapter; importing this file does not load Shiki. */
export function RawCodeBlock({ code, className, language = '', variant = 'default' }: CodeBlockProps) {
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
          <code data-language={displayLanguage}>{code}</code>
        </pre>
      </ScrollRegion>
    </CodeBlockFrame>
  );
}
