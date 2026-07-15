import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { PageHeader } from '@/components/page-header';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogClose, DialogContent, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ScrollRegion } from '@/components/ui/scroll-region';
import { Skeleton } from '@/components/ui/skeleton';
import { StatusLabel } from '@/components/ui/status-label';
import { Table, TableBody, TableCell, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

afterEach(cleanup);

describe('shared UI primitives', () => {
  it('exposes semantic and backward-compatible button variants', () => {
    const variants = [
      ['default', 'ui-button--default'],
      ['brand', 'ui-button--brand'],
      ['secondary', 'ui-button--secondary'],
      ['outline', 'ui-button--outline'],
      ['ghost', 'ui-button--ghost'],
      ['danger', 'ui-button--danger'],
      ['destructive', 'ui-button--danger'],
    ] as const;

    const { rerender } = render(<Button>Connect</Button>);
    for (const [variant, className] of variants) {
      rerender(<Button variant={variant}>Connect</Button>);
      expect(screen.getByRole('button', { name: 'Connect' })).toHaveClass(className);
    }
  });

  it('uses native disabled semantics and stable loading content', () => {
    const { rerender } = render(<Button disabled>Connect endpoint</Button>);
    expect(screen.getByRole('button', { name: 'Connect endpoint' })).toBeDisabled();

    rerender(<Button loading loadingLabel="Connecting endpoint">Connect endpoint</Button>);
    const loading = screen.getByRole('button', { name: 'Connecting endpoint' });
    expect(loading).toBeDisabled();
    expect(loading).toHaveAttribute('aria-busy', 'true');
    expect(loading).toHaveAttribute('data-loading', 'true');
    expect(loading.querySelector('.ui-button__spinner')).toBeInTheDocument();
    expect(loading.querySelector('.ui-button__content')).toHaveTextContent('Connect endpoint');
  });

  it('keeps badge metadata neutral and renders every explicit status tone', () => {
    render(
      <>
        <Badge variant="success">draft</Badge>
        <StatusLabel tone="success">PASS</StatusLabel>
        <StatusLabel tone="warning">UNSUPPORTED</StatusLabel>
        <StatusLabel tone="danger">FAIL</StatusLabel>
        <StatusLabel tone="neutral">NOT REPORTED</StatusLabel>
        <StatusLabel tone="known-peer">KNOWN PEER ISSUE</StatusLabel>
      </>,
    );
    expect(screen.getByText('draft')).toHaveClass('ui-badge');
    expect(screen.getByText('draft')).not.toHaveClass('status-label--success');
    expect(screen.getByText('PASS')).toHaveClass('status-label--success');
    expect(screen.getByText('UNSUPPORTED')).toHaveClass('status-label--warning');
    expect(screen.getByText('FAIL')).toHaveClass('status-label--danger');
    expect(screen.getByText('NOT REPORTED')).toHaveClass('status-label--neutral');
    expect(screen.getByText('KNOWN PEER ISSUE')).toHaveClass('status-label--known-peer');
  });

  it('labels scroll and table wrappers and focuses only actual overflow', async () => {
    render(
      <>
        <ScrollRegion aria-label="Packet timeline">content</ScrollRegion>
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>packet</TableCell>
            </TableRow>
          </TableBody>
        </Table>
        <Table scrollLabel="Interop results">
          <TableBody />
        </Table>
      </>,
    );
    const scroll = screen.getByLabelText('Packet timeline');
    const fallbackTable = screen.getByLabelText('Data table');
    expect(scroll).not.toHaveAttribute('tabindex');
    expect(fallbackTable).not.toHaveAttribute('tabindex');
    expect(screen.getByLabelText('Interop results').querySelector('table')).toBeInTheDocument();

    Object.defineProperties(scroll, {
      clientWidth: { configurable: true, value: 100 },
      scrollWidth: { configurable: true, value: 200 },
    });
    fireEvent(window, new Event('resize'));
    await waitFor(() => expect(screen.getByRole('region', { name: 'Packet timeline' })).toHaveAttribute('tabindex', '0'));

    Object.defineProperties(fallbackTable, {
      clientWidth: { configurable: true, value: 100 },
      scrollWidth: { configurable: true, value: 200 },
    });
    fireEvent(window, new Event('resize'));
    await waitFor(() => expect(screen.getByRole('region', { name: 'Data table' })).toHaveAttribute('tabindex', '0'));
  });

  it('traps dialog interaction, closes on Escape, and restores trigger focus', async () => {
    render(
      <Dialog>
        <DialogTrigger>Inspect packet</DialogTrigger>
        <DialogContent>
          <DialogTitle>Packet detail</DialogTitle>
          <DialogClose>Close detail</DialogClose>
        </DialogContent>
      </Dialog>,
    );
    const trigger = screen.getByRole('button', { name: 'Inspect packet' });
    fireEvent.click(trigger);
    const dialog = await screen.findByRole('dialog', { name: 'Packet detail' });
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    fireEvent.keyDown(dialog, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('uses Radix roving focus and arrow navigation for tabs', async () => {
    render(
      <Tabs defaultValue="client">
        <TabsList aria-label="Endpoint view">
          <TabsTrigger value="client">Client</TabsTrigger>
          <TabsTrigger value="server">Server</TabsTrigger>
        </TabsList>
        <TabsContent value="client">Client packets</TabsContent>
        <TabsContent value="server">Server packets</TabsContent>
      </Tabs>,
    );
    const client = screen.getByRole('tab', { name: 'Client' });
    const server = screen.getByRole('tab', { name: 'Server' });
    client.focus();
    await act(async () => {
      fireEvent.keyDown(client, { key: 'ArrowRight' });
    });
    await waitFor(() => expect(server).toHaveFocus());
    await waitFor(() => expect(server).toHaveAttribute('aria-selected', 'true'));
  });

  it('reserves skeleton geometry without exposing loading noise', () => {
    render(<Skeleton style={{ width: 120, height: 20 }}>ignored</Skeleton>);
    const skeleton = screen.getByText('ignored');
    expect(skeleton).toHaveAttribute('aria-hidden', 'true');
    expect(skeleton).toHaveAttribute('data-skeleton', 'true');
    expect(skeleton).toHaveStyle({ width: '120px', height: '20px' });
  });
});

describe('PageHeader', () => {
  it('keeps the compatible eyebrow/title form with one heading', () => {
    const { container } = render(<PageHeader eyebrow="Evidence" title="Interop" variant="evidence" />);
    expect(screen.getByText('Evidence')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Interop' })).toBeInTheDocument();
    expect(container.querySelector('.page-header__eyebrow-marker')).toHaveAttribute('aria-hidden', 'true');
    expect(container.querySelector('.page-header')).toHaveAttribute('data-page-header-variant', 'evidence');
    expect(container.querySelector('.page-header__context')).toBeInTheDocument();
    expect(container.querySelector('.page-header svg')).not.toBeInTheDocument();
    expect(container.querySelectorAll('h1')).toHaveLength(1);
  });

  it('supports an unframed description, actions, and measure classes', () => {
    const { container } = render(
      <PageHeader
        title="Workbench"
        description="Inspect a real packet flow."
        actions={<Button>Run</Button>}
        containerClassName="container-focused"
        measureClassName="measure-reading"
      />,
    );
    expect(screen.getByText('Inspect a real packet flow.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run' })).toBeInTheDocument();
    expect(container.querySelector('.container-focused')).toBeInTheDocument();
    expect(container.querySelector('.measure-reading')).toBeInTheDocument();
    expect(container.querySelector('.page-header')).toHaveClass('page-header--without-context');
    expect(container.querySelector('article, .ui-panel')).not.toBeInTheDocument();
    expect(container.querySelectorAll('h1')).toHaveLength(1);
  });
});
