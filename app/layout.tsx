import type { Metadata } from "next";
import { ConvexClientProvider } from "./ConvexClientProvider";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://openconsole-araujota97gmailcoms-projects.vercel.app"),
  title: { default: "OpenConsole — boot games, not platforms", template: "%s · OpenConsole" },
  description: "A portable UEFI game console for signed, owned, inspectable games. We have to go where they can’t follow.",
  alternates: { canonical: "/" },
  openGraph: { title: "OpenConsole — boot games, not platforms", description: "Put the EFI and signed games on a USB drive. Carry the console, own the artifacts, skip the operating system.", url: "/", siteName: "OpenConsole", type: "website" },
  twitter: { card: "summary", title: "OpenConsole", description: "We have to go where they can’t follow." },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <ConvexClientProvider>
          {children}
        </ConvexClientProvider>
      </body>
    </html>
  );
}
