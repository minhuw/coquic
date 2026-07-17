'use client';

import * as React from 'react';
import * as DialogPrimitive from '@radix-ui/react-dialog';

import { cn } from '@/lib/utils';

const Dialog = DialogPrimitive.Root;

const DialogTrigger = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Trigger>
>(({ ...props }, ref) => <DialogPrimitive.Trigger ref={ref} {...props} data-slot="dialog-trigger" />);
DialogTrigger.displayName = DialogPrimitive.Trigger.displayName;

const DialogClose = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Close>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Close>
>(({ ...props }, ref) => <DialogPrimitive.Close ref={ref} {...props} data-slot="dialog-close" />);
DialogClose.displayName = DialogPrimitive.Close.displayName;

const DialogTitle = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Title>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(({ ...props }, ref) => <DialogPrimitive.Title ref={ref} {...props} data-slot="dialog-title" />);
DialogTitle.displayName = DialogPrimitive.Title.displayName;

const DialogDescription = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Description>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(({ ...props }, ref) => <DialogPrimitive.Description ref={ref} {...props} data-slot="dialog-description" />);
DialogDescription.displayName = DialogPrimitive.Description.displayName;

const DialogContent = React.forwardRef<
  React.ElementRef<typeof DialogPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay
      className="ui-dialog__overlay fixed inset-0 z-[var(--z-modal)] bg-[var(--scrim)] transition-opacity duration-[var(--motion-slow)] ease-[var(--ease-standard)] data-[state=closed]:opacity-0 motion-reduce:duration-[1ms]"
      data-slot="dialog-overlay"
    />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        'ui-dialog__content fixed left-1/2 top-1/2 z-[var(--z-modal)] grid max-h-[calc(100dvh_-_2_*_var(--space-5))] w-[min(calc(100vw_-_2_*_var(--page-gutter)),var(--dialog-default))] -translate-x-1/2 -translate-y-1/2 overflow-auto rounded-[var(--radius-overlay)] border border-[var(--border-strong)] bg-[var(--surface)] p-[var(--space-5)] text-[var(--text)] shadow-[var(--elevation-modal)] transition-opacity duration-[var(--motion-slow)] ease-[var(--ease-standard)] data-[state=closed]:opacity-0 motion-reduce:duration-[1ms]',
        className,
      )}
      {...props}
      data-slot="dialog-content"
    >
      {children}
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
DialogContent.displayName = DialogPrimitive.Content.displayName;

export { Dialog, DialogClose, DialogContent, DialogDescription, DialogTitle, DialogTrigger };
