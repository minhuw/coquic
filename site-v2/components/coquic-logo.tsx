import { useId } from "react";
import { cn } from "@/lib/utils";

export function CoquicLogo({ className }: { className?: string }) {
  const maskId = useId();

  return (
    <svg
      viewBox="0 0 512 512"
      aria-hidden="true"
      className={cn("text-ink", className)}
    >
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse">
          <rect width="512" height="512" fill="white" />
          <circle cx="256" cy="253" r="96" fill="black" />
          <rect x="82" y="245" width="352" height="20" fill="black" />
          <rect
            x="-59"
            y="296"
            width="89"
            height="128"
            rx="15"
            transform="skewX(45)"
            fill="black"
          />
        </mask>
      </defs>
      <circle
        cx="256"
        cy="253"
        r="171"
        fill="currentColor"
        mask={`url(#${maskId})`}
      />
      <rect
        x="-47"
        y="307"
        width="65"
        height="101"
        rx="9"
        transform="skewX(45)"
        fill="var(--accent)"
      />
    </svg>
  );
}
