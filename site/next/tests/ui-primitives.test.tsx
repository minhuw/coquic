import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import Link from 'next/link';
import { afterEach, describe, expect, it } from 'vitest';

import { PageHeader } from '@/components/page-header';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
      'default',
      'brand',
      'secondary',
      'outline',
      'ghost',
      'danger',
      'destructive',
    ] as const;

    const { rerender } = render(<Button>Connect</Button>);
    for (const variant of variants) {
      rerender(<Button variant={variant}>Connect</Button>);
      expect(screen.getByRole('button', { name: 'Connect' })).toHaveAttribute('data-slot', 'button');
      expect(screen.getByRole('button', { name: 'Connect' })).toHaveAttribute('data-variant', variant);
    }
  });

  it('keeps stable size and slot hooks for compact, icon, and slotted buttons', () => {
    const { rerender } = render(<Button size="sm">Compact</Button>);
    expect(screen.getByRole('button', { name: 'Compact' })).toHaveAttribute('data-size', 'sm');
    expect(screen.getByRole('button', { name: 'Compact' })).toHaveAttribute('data-slot', 'button');

    rerender(<Button size="icon" aria-label="Inspect"><span aria-hidden="true">+</span></Button>);
    expect(screen.getByRole('button', { name: 'Inspect' })).toHaveAttribute('data-size', 'icon');
    expect(screen.getByRole('button', { name: 'Inspect' })).toHaveAttribute('data-slot', 'button');

    rerender(
      <Button asChild>
        <Link href="/docs">Docs</Link>
      </Button>,
    );
    expect(screen.getByRole('link', { name: 'Docs' })).toHaveAttribute('data-slot', 'button');
  });

  it('uses native disabled semantics and stable loading content', () => {
    const { rerender } = render(<Button disabled>Connect endpoint</Button>);
    expect(screen.getByRole('button', { name: 'Connect endpoint' })).toBeDisabled();

    rerender(<Button loading loadingLabel="Connecting endpoint">Connect endpoint</Button>);
    const loading = screen.getByRole('button', { name: 'Connecting endpoint' });
    expect(loading).toBeDisabled();
    expect(loading).toHaveAttribute('aria-busy', 'true');
    expect(loading).toHaveAttribute('data-loading', 'true');
    expect(loading).toHaveAttribute('data-slot', 'button');
    expect(loading.querySelector('[data-slot="button-spinner"]')).toBeInTheDocument();
    expect(loading.querySelector('[data-slot="button-content"]')).toHaveTextContent('Connect endpoint');
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
    expect(screen.getByText('draft')).toHaveAttribute('data-slot', 'badge');
    expect(screen.getByText('draft')).toHaveAttribute('data-variant', 'success');
    expect(screen.getByText('draft')).not.toHaveAttribute('data-tone');
    expect(screen.getByText('PASS')).toHaveAttribute('data-slot', 'status-label');
    expect(screen.getByText('PASS')).toHaveAttribute('data-tone', 'success');
    expect(screen.getByText('UNSUPPORTED')).toHaveAttribute('data-tone', 'warning');
    expect(screen.getByText('FAIL')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByText('NOT REPORTED')).toHaveAttribute('data-tone', 'neutral');
    expect(screen.getByText('KNOWN PEER ISSUE')).toHaveAttribute('data-tone', 'known-peer');
  });

  it('keeps card subcomponents source-owned and slot-addressable', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Packet</CardTitle>
          <CardDescription>Metadata</CardDescription>
        </CardHeader>
        <CardContent>Payload</CardContent>
      </Card>,
    );
    expect(screen.getByText('Packet')).toHaveAttribute('data-slot', 'card-title');
    expect(screen.getByText('Metadata')).toHaveAttribute('data-slot', 'card-description');
    expect(screen.getByText('Payload')).toHaveAttribute('data-slot', 'card-content');
    expect(screen.getByText('Packet').closest('[data-slot="card"]')).toBeInTheDocument();
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
    expect(scroll).toHaveAttribute('data-slot', 'scroll-region');
    expect(fallbackTable).toHaveAttribute('data-slot', 'table-scroll-region');
    expect(scroll).not.toHaveAttribute('tabindex');
    expect(fallbackTable).not.toHaveAttribute('tabindex');
    expect(screen.getByLabelText('Interop results').querySelector('table')).toBeInTheDocument();
    expect(screen.getByLabelText('Interop results').querySelector('[data-slot="table"]')).toBeInTheDocument();

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
    expect(document.querySelector('[data-slot="dialog-overlay"]')).toBeInTheDocument();
    expect(dialog).toHaveAttribute('data-slot', 'dialog-content');
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
    expect(screen.getByRole('tablist')).toHaveAttribute('data-slot', 'tabs-list');
    expect(client).toHaveAttribute('data-slot', 'tabs-trigger');
    expect(screen.getByRole('tabpanel', { name: 'Client' })).toHaveAttribute('data-slot', 'tabs-content');
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
    expect(skeleton).toHaveAttribute('data-slot', 'skeleton');
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
    expect(container.querySelector('.page-header')).toHaveAttribute('data-slot', 'page-header');
    expect(container.querySelector('.page-header__context')).toHaveAttribute('data-slot', 'page-header-context');
    expect(container.querySelector('.page-title')).toHaveAttribute('data-slot', 'page-header-title');
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
    expect(container.querySelector('.page-header__description')).toHaveAttribute('data-slot', 'page-header-description');
    expect(container.querySelector('.page-header__actions')).toHaveAttribute('data-slot', 'page-header-actions');
    expect(container.querySelector('article, .ui-panel')).not.toBeInTheDocument();
    expect(container.querySelectorAll('h1')).toHaveLength(1);
  });
});
