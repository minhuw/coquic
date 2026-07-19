import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { CodexTranscriptThread, transcriptDisplayCount } from '@/components/codex-transcript-thread';
import { EvidenceDisclosure } from '@/components/evidence/disclosure';
import { CodeBlock, getEvidenceTokenizationCount } from '@/components/evidence/code-block';
import { TranscriptView } from '@/components/steward-transcript';
import {
  conversationKind,
  groupConversationRecords,
  normalizedRole,
  parseCodexTranscriptText,
  toolDisplayName,
  toolPayloadLabel,
  type TranscriptRecord,
} from '@/lib/codex-transcript';

afterEach(() => {
  cleanup();
  document.documentElement.removeAttribute('data-theme');
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1024 });
  vi.unstubAllGlobals();
});

describe('evidence fixtures before consolidation', () => {
  it('locks parser records, grouping order, display count, and disclosure defaults', () => {
    const records = parseCodexTranscriptText(
      [
        JSON.stringify({
          timestamp: '2026-07-14T10:00:00Z',
          type: 'response_item',
          payload: { type: 'message', role: 'user', content: 'Inspect the connection.' },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:01Z',
          item: { type: 'agent_message', id: 'message-1', text: 'I will inspect the connection.' },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:02Z',
          item: { type: 'reasoning', id: 'reasoning-1', text: 'Checking the packet path.' },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:03Z',
          item: {
            type: 'command_execution',
            id: 'call-paired',
            command: 'zig build test',
            aggregated_output: 'all tests passed',
          },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:04Z',
          type: 'response_item',
          payload: {
            type: 'custom_tool_call',
            call_id: 'call-unpaired',
            name: 'inspect_packet',
            arguments: { packet: 1 },
          },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:05Z',
          type: 'response_item',
          payload: {
            type: 'custom_tool_call_output',
            call_id: 'result-unpaired',
            output: 'result without a call',
          },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:06Z',
          item: {
            type: 'file_change',
            id: 'file-1',
            status: 'completed',
            changes: [{ kind: 'modified', path: 'src/main.zig' }],
          },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:07Z',
          item: {
            type: 'todo_list',
            id: 'todo-1',
            items: [{ text: 'Review the diff', completed: false }],
          },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:08Z',
          item: { type: 'web_search_call', id: 'search-1', query: 'QUIC packet protection' },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:09Z',
          item: { type: 'error', id: 'error-1', message: 'The packet could not be decoded.' },
        }),
        JSON.stringify({
          timestamp: '2026-07-14T10:00:10Z',
          item: {
            type: 'agent_message',
            id: 'message-2',
            text: '```zig\nconst packet = 1;\n```\n\n![capture](capture.png)\n\n@@ -1 +1 @@\n-old\n+new',
          },
        }),
      ].join('\n'),
    );

    expect(records.map((record) => record.payloadType)).toEqual([
      'message',
      'message',
      'reasoning',
      'command_execution',
      'command_execution_output',
      'custom_tool_call',
      'custom_tool_call_output',
      'file_change',
      'todo_list',
      'web_search_call',
      'error',
      'message',
    ]);
    expect(records[0] && normalizedRole(records[0])).toBe('user');
    expect(records[2] && conversationKind(records[2])).toBe('reasoning');
    expect(toolDisplayName(records[3])).toBe('command');
    expect(toolPayloadLabel(records[5].payloadType)).toBe('custom');

    const items = groupConversationRecords(records);
    expect(items.map((item) => item.type === 'tool' ? `${item.call?.payloadType ?? 'none'}:${item.result?.payloadType ?? 'none'}` : item.record.payloadType)).toEqual([
      'message',
      'message',
      'reasoning',
      'command_execution:command_execution_output',
      'custom_tool_call:none',
      'none:custom_tool_call_output',
      'file_change:none',
      'todo_list:none',
      'web_search_call:none',
      'error',
      'message',
    ]);
    expect(transcriptDisplayCount(records)).toBe(items.length);

    render(<CodexTranscriptThread records={records} />);

    expect(screen.getAllByText('User').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Assistant').length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { name: 'Reasoning' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'command' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'File change' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Task plan' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Web search' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Runtime notice' })).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /command/ })).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByRole('button', { name: /inspect_packet/ })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: /Runtime notice/ })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByAltText('capture')).toHaveAttribute('src', 'capture.png');
  });

  it('retains truncation safeguards and planner prompt/decision display contracts', () => {
    const [truncated] = parseCodexTranscriptText(
      JSON.stringify({ item: { type: 'agent_message', id: 'large-1', text: '1234567890' } }),
      { maxRecordTextLength: 5 },
    );
    expect(truncated).toMatchObject({ textTruncated: true });
    expect(truncated.text).toContain('Preview truncated');

    render(
      <TranscriptView
        prompt={[
          "CoQUIC Steward's planning brain",
          'Decide which maintenance tasks should exist.',
          'Review active_tasks before proposing anything.',
          'Return only JSON matching the requested schema.',
          'Planning input JSON:',
          JSON.stringify({ active_tasks: [], signal_items: [], repository: 'minhuw/coquic' }),
        ].join('\n')}
        taskId="task-fixture"
        text={JSON.stringify({
          consumed_item_ids: ['signal-1'],
          tasks: [{ title: 'Review packet path', kind: 'maintenance', evidence: ['signal-1'] }],
        })}
      />,
    );

    expect(screen.getByText('Planner instructions')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Planner input context' })).toBeInTheDocument();
    expect(screen.getByText('Scheduling decision')).toBeInTheDocument();
    expect(screen.getByText('Review packet path')).toBeInTheDocument();
  });
});

describe('shared evidence primitives', () => {
  it('uses a native disclosure button with explicit state and outcome text', () => {
    render(
      <EvidenceDisclosure icon={<span>!</span>} label="Completed tool" metadata="call + result" tone="success">
        <p>Tool output</p>
      </EvidenceDisclosure>,
    );

    const disclosure = screen.getByRole('button', { name: /Completed tool/ });
    expect(disclosure.tagName).toBe('BUTTON');
    expect(disclosure).toHaveAttribute('type', 'button');
    expect(disclosure).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByRole('heading', { name: 'Completed tool' })).toBeInTheDocument();
    expect(screen.getByText('Complete')).toBeInTheDocument();

    disclosure.focus();
    expect(document.activeElement).toBe(disclosure);
    fireEvent.click(disclosure);
    expect(disclosure).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('Tool output')).toBeInTheDocument();
    fireEvent.click(disclosure);
    expect(disclosure).toHaveAttribute('aria-expanded', 'false');
  });

  it('labels pending and dangerous outcomes instead of relying on color', () => {
    render(
      <>
        <EvidenceDisclosure icon={<span>?</span>} label="Pending tool" tone="warning"><p>Waiting</p></EvidenceDisclosure>
        <EvidenceDisclosure icon={<span>!</span>} label="Failed tool" tone="danger"><p>Failed</p></EvidenceDisclosure>
      </>,
    );

    expect(screen.getByText('Pending')).toBeInTheDocument();
    expect(screen.getByText('Attention')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Pending tool/ })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: /Failed tool/ })).toHaveAttribute('aria-expanded', 'true');
  });

  it('keeps dual-theme tokens aligned and does not retokenize on theme changes', async () => {
    const text = 'const evidenceThemeCacheFixture = true;';
    const before = getEvidenceTokenizationCount();
    const { container, rerender } = render(<CodeBlock language="typescript" text={text} title="Theme fixture" />);
    await waitFor(() => expect(container.querySelector('[data-evidence-tokenized="true"]')).toBeInTheDocument());

    const token = container.querySelector<HTMLElement>('[data-evidence-token]');
    expect(token).not.toBeNull();
    expect(token?.style.getPropertyValue('--shiki-light')).not.toBe('');
    expect(token?.style.getPropertyValue('--shiki-dark')).not.toBe('');
    const afterTokenization = getEvidenceTokenizationCount();
    expect(afterTokenization).toBe(before + 1);

    document.documentElement.dataset.theme = 'dark';
    rerender(<CodeBlock language="typescript" text={text} title="Theme fixture" />);
    expect(getEvidenceTokenizationCount()).toBe(afterTokenization);
    expect(container.textContent).toContain('evidenceThemeCacheFixture');
  });

  it('falls back for unknown and long-line input while preserving copy and local scroll semantics', async () => {
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    vi.stubGlobal('navigator', { clipboard });
    const longLine = 'x'.repeat(3500);
    const { container } = render(<CodeBlock language="unknown-language" text={longLine} title="Plain fixture" />);
    const region = container.querySelector<HTMLElement>('[data-scroll-region="true"]');
    expect(region).toHaveAttribute('aria-label', 'Plain fixture code');
    expect(container.textContent).toContain(longLine);

    if (region) {
      Object.defineProperty(region, 'scrollWidth', { configurable: true, value: 500 });
      Object.defineProperty(region, 'clientWidth', { configurable: true, value: 100 });
      fireEvent(window, new Event('resize'));
      expect(region).toHaveAttribute('role', 'region');
      expect(region).toHaveAttribute('tabindex', '0');
    }

    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith(longLine));
    expect(screen.getByRole('button', { name: 'Code copied' })).toBeInTheDocument();
    expect(screen.getByText('Code copied')).toBeInTheDocument();
  });

  it('preserves a known-language long line through bounded Shiki tokenization or fallback', async () => {
    const source = `const knownLanguageLongLine = "${'x'.repeat(3500)}";`;
    const before = getEvidenceTokenizationCount();
    const { container } = render(<CodeBlock language="typescript" text={source} title="Known long line" />);

    await waitFor(() => expect(getEvidenceTokenizationCount()).toBe(before + 1));
    const block = container.querySelector('[data-evidence-code-block="true"]');
    expect(block).toHaveAttribute('data-evidence-tokenized');
    expect(block).toHaveTextContent(source);
    expect(container.querySelector('[data-scroll-region="true"]')).toHaveAttribute('aria-label', 'Known long line code');
  });

  it('keeps the shared diff dialog trapped, scrim-closable, and usable at 320px', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 320 });
    render(<CodeBlock diffDisplay="unified-with-split-modal" language="diff" text="@@ -1 +1 @@\n-old\n+new\n" title="Small diff" />);

    const trigger = screen.getByRole('button', { name: 'Open side-by-side diff' });
    fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Small diff side-by-side' });
    const close = screen.getByRole('button', { name: 'Close side-by-side diff' });
    expect(dialog).toBeInTheDocument();
    expect(close).toHaveAttribute('type', 'button');
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(close);

    const overlay = document.querySelector('[data-slot="dialog-overlay"]');
    expect(overlay).not.toBeNull();
    await new Promise((resolve) => window.setTimeout(resolve, 0));
    fireEvent.pointerDown(overlay as Element, { button: 0 });
    fireEvent.click(overlay as Element);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);
  });
});

export function fixtureRecord(overrides: Partial<TranscriptRecord> = {}): TranscriptRecord {
  return {
    line: 1,
    timestamp: '',
    type: 'item',
    role: 'assistant',
    payloadType: 'message',
    text: 'fixture text',
    eventKind: 'item:message',
    toolName: '',
    toolCallId: '',
    textTruncated: false,
    ...overrides,
  };
}
