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
        className="table-scroll-region"
        aria-label={scrollLabel}
        data-overflow={overflowing || undefined}
        role={overflowing ? 'region' : undefined}
        tabIndex={overflowing ? 0 : undefined}
      >
        <table ref={ref} className={cn('ui-table', className)} {...props} />
      </div>
    );
  },
);
Table.displayName = 'Table';

const TableHeader = React.forwardRef<HTMLTableSectionElement, React.HTMLAttributes<HTMLTableSectionElement>>(
  ({ className, ...props }, ref) => <thead ref={ref} className={cn('ui-table__header', className)} {...props} />,
);
TableHeader.displayName = 'TableHeader';

const TableBody = React.forwardRef<HTMLTableSectionElement, React.HTMLAttributes<HTMLTableSectionElement>>(
  ({ className, ...props }, ref) => <tbody ref={ref} className={cn('ui-table__body', className)} {...props} />,
);
TableBody.displayName = 'TableBody';

const TableRow = React.forwardRef<HTMLTableRowElement, React.HTMLAttributes<HTMLTableRowElement>>(
  ({ className, ...props }, ref) => <tr ref={ref} className={cn('ui-table__row', className)} {...props} />,
);
TableRow.displayName = 'TableRow';

const TableHead = React.forwardRef<HTMLTableCellElement, React.ThHTMLAttributes<HTMLTableCellElement>>(
  ({ className, ...props }, ref) => <th ref={ref} className={cn('ui-table__head', className)} {...props} />,
);
TableHead.displayName = 'TableHead';

const TableCell = React.forwardRef<HTMLTableCellElement, React.TdHTMLAttributes<HTMLTableCellElement>>(
  ({ className, ...props }, ref) => <td ref={ref} className={cn('ui-table__cell', className)} {...props} />,
);
TableCell.displayName = 'TableCell';

export { Table, TableBody, TableCell, TableHead, TableHeader, TableRow };
