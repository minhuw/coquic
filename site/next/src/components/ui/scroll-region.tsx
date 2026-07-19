'use client';

import * as React from 'react';

import { cn } from '@/lib/utils';

type OverflowAxis = 'horizontal' | 'vertical' | 'both';

function isOverflowing(element: HTMLElement, axis: OverflowAxis) {
  const horizontal = element.scrollWidth > element.clientWidth;
  const vertical = element.scrollHeight > element.clientHeight;
  return axis === 'horizontal' ? horizontal : axis === 'vertical' ? vertical : horizontal || vertical;
}

const axisClasses: Record<OverflowAxis, string> = {
  horizontal: 'overflow-x-auto',
  vertical: 'overflow-y-auto',
  both: 'overflow-x-auto overflow-y-auto',
};

export function useOverflow<T extends HTMLElement>(axis: OverflowAxis = 'both') {
  const ref = React.useRef<T>(null);
  const [overflowing, setOverflowing] = React.useState(false);

  React.useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;

    const update = () => setOverflowing(isOverflowing(element, axis));
    const resizeObserver = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(update);
    const observeSizes = () => {
      resizeObserver?.disconnect();
      resizeObserver?.observe(element);
      for (const child of element.children) resizeObserver?.observe(child);
      update();
    };
    const mutationObserver =
      typeof MutationObserver === 'undefined' ? null : new MutationObserver(observeSizes);

    observeSizes();
    mutationObserver?.observe(element, { childList: true, characterData: true, subtree: true });
    window.addEventListener('resize', update);
    return () => {
      mutationObserver?.disconnect();
      resizeObserver?.disconnect();
      window.removeEventListener('resize', update);
    };
  }, [axis]);

  return { ref, overflowing };
}

export interface ScrollRegionProps extends React.HTMLAttributes<HTMLDivElement> {
  'aria-label': string;
  axis?: OverflowAxis;
}

const ScrollRegion = React.forwardRef<HTMLDivElement, ScrollRegionProps>(
  ({ className, axis = 'both', tabIndex, ...props }, forwardedRef) => {
    const { ref, overflowing } = useOverflow<HTMLDivElement>(axis);
    React.useImperativeHandle(forwardedRef, () => ref.current as HTMLDivElement);
    return (
      <div
        ref={ref}
        className={cn(
          'relative max-w-full overscroll-contain data-[overflow=true]:shadow-[inset_-10px_0_10px_-12px_var(--text-muted)]',
          axisClasses[axis],
          className,
        )}
        data-overflow={overflowing || undefined}
        data-scroll-region="true"
        role={overflowing ? 'region' : undefined}
        tabIndex={overflowing ? (tabIndex ?? 0) : undefined}
        {...props}
        data-slot="scroll-region"
      />
    );
  },
);
ScrollRegion.displayName = 'ScrollRegion';

export { ScrollRegion };
