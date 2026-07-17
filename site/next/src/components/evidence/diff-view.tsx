'use client';

import { Fragment } from 'react';

import { ScrollRegion } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

import styles from './diff-view.module.css';

export type DiffCell = { kind: 'added' | 'context' | 'empty' | 'removed'; lineNumber: string; text: string };
export type DiffMetaVariant = 'file' | 'hunk' | 'plain';
export type DiffSplitRow =
  | { kind: 'content'; oldCell: DiffCell; newCell: DiffCell }
  | { kind: 'meta'; text: string; variant: DiffMetaVariant };
export type DiffViewDisplay = 'split' | 'unified';

export function DiffView({
  className = '',
  display,
  rows,
  showLineNumbers,
}: {
  className?: string;
  display: DiffViewDisplay;
  rows: DiffSplitRow[];
  showLineNumbers: boolean;
}) {
  const label = display === 'split' ? 'Side-by-side diff' : 'Unified diff';
  return (
    <ScrollRegion aria-label={label} axis="both" className={cn(styles.root, 'evidence-diff-scroll', className)}>
      {display === 'split' ? (
        <SplitDiffTable rows={rows} showLineNumbers={showLineNumbers} />
      ) : (
        <UnifiedDiffTable rows={rows} showLineNumbers={showLineNumbers} />
      )}
    </ScrollRegion>
  );
}

function SplitDiffTable({ rows, showLineNumbers }: { rows: DiffSplitRow[]; showLineNumbers: boolean }) {
  return (
    <div className={cn(styles.split, 'diff-split')} role="table" aria-label="Side-by-side diff contents">
      <div className={cn(styles.splitHeader, 'diff-split-header')} role="row">
        <div className={cn(styles.splitColumnLabel, 'diff-split-column-label')} role="columnheader">Old</div>
        <div className={cn(styles.splitColumnLabel, 'diff-split-column-label')} role="columnheader">New</div>
      </div>
      <div className={cn(styles.splitBody, 'diff-split-body')}>
        {rows.map((row, index) =>
          row.kind === 'meta' ? (
            <div className={cn(styles.splitMeta, row.variant === 'file' && styles.metaFile, 'diff-split-meta', row.variant)} key={index} role="row">
              <div aria-colspan={2} className={styles.metaCell} role="cell">
                {row.text.split('\n').map((line, lineIndex) => <span key={lineIndex}>{line || ' '}</span>)}
              </div>
            </div>
          ) : (
            <div className={cn(styles.splitRow, 'diff-split-row')} key={index} role="row">
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
    <div className={cn(styles.splitCell, cell.kind === 'added' && styles.splitCellAdded, cell.kind === 'removed' && styles.splitCellRemoved, cell.kind === 'empty' && styles.splitCellEmpty, 'diff-split-cell', cell.kind)} role="cell">
      <span className={cn(styles.splitLineNumber, 'diff-split-line-number')}>{showLineNumbers ? cell.lineNumber || ' ' : ' '}</span>
      <span className={cn(styles.splitMarker, 'diff-split-marker')}>{diffMarker(cell.kind)}</span>
      <span className={cn(styles.splitContent, 'diff-split-content')}>{cell.text || ' '}</span>
    </div>
  );
}

function UnifiedDiffTable({ rows, showLineNumbers }: { rows: DiffSplitRow[]; showLineNumbers: boolean }) {
  return (
    <div className={cn(styles.unified, !showLineNumbers && styles.unifiedNoLineNumbers, 'diff-unified', !showLineNumbers && 'no-line-numbers')} role="table" aria-label="Unified diff contents">
      {rows.map((row, index) => {
        if (row.kind === 'meta') {
          return (
            <div className={cn(styles.unifiedMeta, row.variant === 'file' && styles.metaFile, 'diff-unified-meta', row.variant)} key={index} role="row">
              <div aria-colspan={showLineNumbers ? 4 : 2} className={styles.metaCell} role="cell">
                {row.text.split('\n').map((line, lineIndex) => <span key={lineIndex}>{line || ' '}</span>)}
              </div>
            </div>
          );
        }
        if (row.oldCell.kind === 'context' && row.newCell.kind === 'context') {
          return (
            <UnifiedDiffLine
              cell={row.oldCell}
              key={index}
              newLineNumber={row.newCell.lineNumber}
              oldLineNumber={row.oldCell.lineNumber}
              showLineNumbers={showLineNumbers}
            />
          );
        }
        return (
          <Fragment key={index}>
            {row.oldCell.kind !== 'empty' ? (
              <UnifiedDiffLine
                cell={row.oldCell}
                newLineNumber=""
                oldLineNumber={row.oldCell.lineNumber}
                showLineNumbers={showLineNumbers}
              />
            ) : null}
            {row.newCell.kind !== 'empty' ? (
              <UnifiedDiffLine
                cell={row.newCell}
                newLineNumber={row.newCell.lineNumber}
                oldLineNumber=""
                showLineNumbers={showLineNumbers}
              />
            ) : null}
          </Fragment>
        );
      })}
    </div>
  );
}

function UnifiedDiffLine({
  cell,
  newLineNumber,
  oldLineNumber,
  showLineNumbers,
}: {
  cell: DiffCell;
  newLineNumber: string;
  oldLineNumber: string;
  showLineNumbers: boolean;
}) {
  return (
    <div className={cn(styles.unifiedLine, cell.kind === 'added' && styles.unifiedLineAdded, cell.kind === 'removed' && styles.unifiedLineRemoved, 'diff-unified-line', cell.kind)} role="row">
      {showLineNumbers ? (
        <>
          <span className={cn(styles.unifiedLineNumber, styles.unifiedOld, 'diff-unified-line-number', 'old')} role="cell">{oldLineNumber || ' '}</span>
          <span className={cn(styles.unifiedLineNumber, styles.unifiedNew, 'diff-unified-line-number', 'new')} role="cell">{newLineNumber || ' '}</span>
        </>
      ) : null}
      <span className={cn(styles.unifiedMarker, 'diff-unified-marker')} role="cell">{diffMarker(cell.kind)}</span>
      <span className={cn(styles.unifiedContent, 'diff-unified-content')} role="cell">{cell.text || ' '}</span>
    </div>
  );
}

export function buildSplitDiffRows(lines: string[]): DiffSplitRow[] {
  const rows: DiffSplitRow[] = [];
  let pendingMeta: string[] = [];
  let pendingMetaVariant: DiffMetaVariant = 'plain';
  let pendingRemoved: DiffCell[] = [];
  let pendingAdded: DiffCell[] = [];
  let oldLine: number | null = null;
  let newLine: number | null = null;

  function appendMeta(line: string, variant: DiffMetaVariant) {
    if (variant === 'file' && line.startsWith('diff --git ') && pendingMeta.length) flushMeta();
    pendingMeta.push(line);
    if (variant === 'file') pendingMetaVariant = 'file';
  }

  function flushMeta() {
    if (!pendingMeta.length) return;
    rows.push({ kind: 'meta', text: pendingMeta.join('\n'), variant: pendingMetaVariant });
    pendingMeta = [];
    pendingMetaVariant = 'plain';
  }

  function flushPending() {
    const rowCount = Math.max(pendingRemoved.length, pendingAdded.length);
    for (let index = 0; index < rowCount; index += 1) {
      rows.push({ kind: 'content', oldCell: pendingRemoved[index] ?? emptyDiffCell(), newCell: pendingAdded[index] ?? emptyDiffCell() });
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
      rows.push({ kind: 'meta', text: line, variant: 'hunk' });
      return;
    }
    if (isDiffFileHeader(line) || line.startsWith('diff --git ') || line.startsWith('index ') || line.startsWith('\\')) {
      flushPending();
      appendMeta(line, isDiffFileHeader(line) || line.startsWith('diff --git ') ? 'file' : 'plain');
      return;
    }
    if (line === '' && index === lines.length - 1) {
      flushMeta();
      flushPending();
      return;
    }
    if (oldLine === null || newLine === null) {
      flushPending();
      appendMeta(line, 'plain');
      return;
    }
    if (line.startsWith('+') && !line.startsWith('+++')) {
      flushMeta();
      pendingAdded.push({ kind: 'added', lineNumber: String(newLine), text: line.slice(1) });
      newLine += 1;
      return;
    }
    if (line.startsWith('-') && !line.startsWith('---')) {
      flushMeta();
      if (pendingAdded.length) flushPending();
      pendingRemoved.push({ kind: 'removed', lineNumber: String(oldLine), text: line.slice(1) });
      oldLine += 1;
      return;
    }
    flushMeta();
    flushPending();
    const text = line.startsWith(' ') ? line.slice(1) : line;
    rows.push({ kind: 'content', oldCell: { kind: 'context', lineNumber: String(oldLine), text }, newCell: { kind: 'context', lineNumber: String(newLine), text } });
    oldLine += 1;
    newLine += 1;
  });
  flushMeta();
  flushPending();
  return rows;
}

function isDiffFileHeader(line: string) {
  return line.startsWith('--- ') || line.startsWith('+++ ');
}

function emptyDiffCell(): DiffCell {
  return { kind: 'empty', lineNumber: '', text: '' };
}

function diffMarker(kind: DiffCell['kind']) {
  if (kind === 'added') return '+';
  if (kind === 'removed') return '-';
  return ' ';
}
