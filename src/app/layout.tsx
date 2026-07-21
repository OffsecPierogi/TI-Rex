import "./globals.css";
import { getSession } from "@/lib/auth";
import { Sidebar } from "@/components/layout/Sidebar";
import { prisma } from "@/lib/db";

export const metadata = {
  title: "TI-Rex",
  description: "Open-source threat intelligence platform powered by MITRE ATT&CK",
};

async function getUnreadAlertCount(userId: string): Promise<number> {
  try {
    return await prisma.watchlistAlert.count({
      where: { watchlist: { userId }, read: false },
    });
  } catch {
    return 0;
  }
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await getSession();
  const alertCount = user ? await getUnreadAlertCount(user.id) : 0;

  return (
    <html lang="en" className="dark">
      <body className={user ? "flex min-h-screen" : "min-h-screen"}>
        {user && <Sidebar user={user} alertCount={alertCount} />}
        <main className={user ? "flex-1 ml-64 p-6 overflow-y-auto" : ""}>
          {children}
        </main>
      </body>
    </html>
  );
}
