import "./globals.css";
import Nav from "@/components/Nav";

export const metadata = {
  title: "SentinelOps",
  description: "Authorized penetration-testing engagement platform",
};

// Applies the saved theme before first paint so the page does not flash dark -> light.
const themeInit = `try{var t=localStorage.getItem("so-theme");if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t)}}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInit }} />
      </head>
      <body>
        <Nav />
        {children}
      </body>
    </html>
  );
}
