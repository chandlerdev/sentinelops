import Nav from "@/components/Nav";

export const metadata = {
  title: "SentinelOps",
  description: "Authorized penetration-testing engagement platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{
        fontFamily: "system-ui, sans-serif", margin: 0,
        background: "#0f1115", color: "#e6e9ef",
      }}>
        <Nav />
        {children}
      </body>
    </html>
  );
}
