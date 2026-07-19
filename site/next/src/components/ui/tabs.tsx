'use client';

import * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';

import { cn } from '@/lib/utils';

const Tabs = TabsPrimitive.Root;

const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.List
    ref={ref}
    className={cn('flex min-w-0 gap-[var(--space-1)] border-b border-[var(--border)]', className)}
    {...props}
    data-slot="tabs-list"
  />
));
TabsList.displayName = TabsPrimitive.List.displayName;

const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      'inline-flex min-h-[var(--control-default)] min-w-0 items-center justify-center border-0 border-b-2 border-transparent bg-transparent px-[var(--space-3)] text-[var(--text-muted)] tracking-[0] [font:var(--type-ui-label)] focus-visible:outline-2 focus-visible:outline-offset-3 focus-visible:outline-[var(--accent-ink)] data-[state=active]:border-b-[var(--accent-ink)] data-[state=active]:text-[var(--text-strong)]',
      className,
    )}
    {...props}
    data-slot="tabs-trigger"
  />
));
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName;

const TabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn('py-[var(--space-4)]', className)}
    {...props}
    data-slot="tabs-content"
  />
));
TabsContent.displayName = TabsPrimitive.Content.displayName;

export { Tabs, TabsContent, TabsList, TabsTrigger };
