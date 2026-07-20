import type { Metadata } from "next";
import "@fontsource-variable/google-sans-code";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "CoQUIC Observatory",
    template: "%s | CoQUIC Observatory",
  },
  description:
    "An inspectable research environment for an experimental QUIC and HTTP/3 implementation.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
