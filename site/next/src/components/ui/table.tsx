'use client';

import * as React from 'react';

import { useOverflow } from '@/components/ui/scroll-region';
import { cn } from '@/lib/utils';

export interface TableProps extends React.TableHTMLAttributes<HTMLTableElement> {
  scrollLabel?: string;
}

const Table = React.forwardRef<HTMLTableElement, TableProps>(
  ({ className, scrollLabel = 'Data table', ...props }, ref) => {
    const { ref: scrollRef, overflowing } = useOverflow<HTMLDivElement>('horizontal');
    return (
      <div
        ref={scrollRef}
        className="table-scroll-region relative max-w-full overflow-x-auto overscroll-contain data-[overflow=true]:shadow-[inset_-10px_0_10px_-12px_var(--text-muted)]"
        aria-label={scrollLabel}
        data-overflow={overflowing || undefined}
        role={overflowing ? 'region' : undefined}
        tabIndex={overflowing ? 0 : undefined}
        data-slot="table-scroll-region"
      >
        <table
          ref={ref}
          className={cn('ui-table w-full border-collapse caption-bottom text-sm', className)}
          {...props}
          data-slot="table"
        />
      </div>
    );
  },
);
Table.displayName = 'Table';

const TableHeader = React.forwardRef<HTMLTableSectionElement, React.HTMLAttributes<HTMLTableSectionElement>>(
  ({ className, ...props }, ref) => (
    <thead ref={ref} className={cn('ui-table__header', className)} {...props} data-slot="table-header" />
  ),
);
TableHeader.displayName = 'TableHeader';

const TableBody = React.forwardRef<HTMLTableSectionElement, React.HTMLAttributes<HTMLTableSectionElement>>(
  ({ className, ...props }, ref) => (
    <tbody ref={ref} className={cn('ui-table__body', className)} {...props} data-slot="table-body" />
  ),
);
TableBody.displayName = 'TableBody';

const TableRow = React.forwardRef<HTMLTableRowElement, React.HTMLAttributes<HTMLTableRowElement>>(
  ({ className, ...props }, ref) => (
    <tr
      ref={ref}
      className={cn('ui-table__row border-b border-[var(--border)] hover:bg-[var(--surface-subtle)]', className)}
      {...props}
      data-slot="table-row"
    />
  ),
);
TableRow.displayName = 'TableRow';

const TableHead = React.forwardRef<HTMLTableCellElement, React.ThHTMLAttributes<HTMLTableCellElement>>(
  ({ className, ...props }, ref) => (
    <th
      ref={ref}
      className={cn(
        'ui-table__head h-10 px-[var(--space-3)] text-left align-middle text-[var(--text-muted)] tracking-[0] [font:var(--type-metadata)]',
        className,
      )}
      {...props}
      data-slot="table-head"
    />
  ),
);
TableHead.displayName = 'TableHead';

const TableCell = React.forwardRef<HTMLTableCellElement, React.TdHTMLAttributes<HTMLTableCellElement>>(
  ({ className, ...props }, ref) => (
    <td
      ref={ref}
      className={cn('ui-table__cell p-[var(--space-3)] align-middle text-[var(--text)]', className)}
      {...props}
      data-slot="table-cell"
    />
  ),
);
TableCell.displayName = 'TableCell';

export { Table, TableBody, TableCell, TableHead, TableHeader, TableRow };
