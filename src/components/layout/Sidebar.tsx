"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  LayoutDashboard,
  Globe,
  Grid3x3,
  Zap,
  Skull,
  Bug,
  Wrench,
  Radio,
  Satellite,
  ShieldAlert,
  Terminal,
  Shield,
  FileCode,
  Dna,
  Target,
  Map,
  AlertTriangle,
  Crosshair,
  FlaskConical,
  Lock,
  Tags,
  FileText,
  Rss,
  ShieldCheck,
  BarChart3,
  Share2,
  Search,
  Settings,
  ChevronDown,
  Combine,
  LogOut,
  User,
  Eye,
} from "lucide-react";
import { TIRexLogo } from "./TIRexLogo";
import { logout } from "@/actions/auth";

type NavItem = { href: string; label: string; icon: React.ComponentType<{ className?: string }> };

interface NavSection {
  label: string;
  items: NavItem[];
  defaultOpen?: boolean;
}

interface SidebarUser {
  email: string;
  name: string | null;
  role: string;
}

const SECTIONS: NavSection[] = [
  {
    label: "Overview",
    defaultOpen: true,
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/geo", label: "Geo Heatmap", icon: Globe },
      { href: "/matrix", label: "ATT&CK Matrix", icon: Grid3x3 },
    ],
  },
  {
    label: "Threat Landscape",
    defaultOpen: true,
    items: [
      { href: "/actors", label: "Threat Actors", icon: Skull },
      { href: "/malware", label: "Malware", icon: Bug },
      { href: "/techniques", label: "Techniques", icon: Zap },
      { href: "/tools", label: "Tools", icon: Wrench },
      { href: "/c2", label: "C2 Profiles", icon: Radio },
      { href: "/satcom", label: "SATCOM Intel", icon: Satellite },
      { href: "/cves", label: "CVEs / KEV", icon: ShieldAlert },
    ],
  },
  {
    label: "Detection & Offense",
    items: [
      { href: "/commands", label: "Commands", icon: Terminal },
      { href: "/detections", label: "Detections", icon: Shield },
      { href: "/coverage", label: "Coverage", icon: BarChart3 },
      { href: "/sigma-generator", label: "Sigma Gen", icon: FileCode },
      { href: "/yara", label: "YARA Rules", icon: Dna },
      { href: "/purple-team", label: "Purple Team", icon: Target },
    ],
  },
  {
    label: "Analysis",
    items: [
      { href: "/navigator", label: "Navigator", icon: Map },
      { href: "/correlations", label: "Correlations", icon: Combine },
      { href: "/advisories", label: "Advisories", icon: AlertTriangle },
      { href: "/iocs", label: "IOCs", icon: Crosshair },
      { href: "/watchlist", label: "Watchlist", icon: Eye },
      { href: "/sandbox", label: "Sandbox", icon: FlaskConical },
      { href: "/ransomware", label: "Ransomware", icon: Lock },
      { href: "/categories", label: "Categories", icon: Tags },
      { href: "/threat-model", label: "Threat Model", icon: ShieldCheck },
    ],
  },
  {
    label: "Output",
    items: [
      { href: "/reports", label: "Reports", icon: FileText },
      { href: "/stix", label: "STIX Export", icon: Share2 },
      { href: "/feeds", label: "Threat Feeds", icon: Rss },
    ],
  },
];

const BOTTOM_ITEMS: NavItem[] = [
  { href: "/search", label: "Search", icon: Search },
  { href: "/settings", label: "Settings", icon: Settings },
];

const ROLE_COLORS: Record<string, string> = {
  ADMIN: "text-red-400",
  EDITOR: "text-amber-400",
  READER: "text-emerald-400",
};

function CollapsibleSection({
  section,
  pathname,
  badges,
}: {
  section: NavSection;
  pathname: string;
  badges?: Record<string, number>;
}) {
  const [open, setOpen] = useState(true);

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-2 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
      >
        {section.label}
        <ChevronDown
          className={`w-3 h-3 transition-transform ${open ? "" : "-rotate-90"}`}
        />
      </button>
      {open && (
        <div className="space-y-0.5">
          {section.items.map((item) => {
            const Icon = item.icon;
            const badgeCount = badges?.[item.href] ?? 0;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`sidebar-link ${pathname.startsWith(item.href) ? "active" : ""}`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {item.label}
                {badgeCount > 0 && (
                  <span className="ml-auto px-1.5 py-0.5 rounded-full bg-red-900/60 text-red-400 text-[10px] font-semibold leading-none">
                    {badgeCount > 99 ? "99+" : badgeCount}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function Sidebar({ user, alertCount = 0 }: { user: SidebarUser; alertCount?: number }) {
  const pathname = usePathname();
  const badges: Record<string, number> = {};
  if (alertCount > 0) badges["/watchlist"] = alertCount;

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-[var(--bg-secondary)] border-r border-[var(--border)] flex flex-col z-50">
      <div className="border-b border-[var(--border)]">
        <div className="flex justify-center pt-4 pb-2">
          <TIRexLogo className="w-28 h-28" />
        </div>
        <div className="text-center pb-3">
          <h1 className="text-xl font-black tracking-tight">
            <span className="text-emerald-400">TI</span>
            <span className="text-[var(--text-primary)]">-Rex</span>
          </h1>
          <p className="text-[10px] text-[var(--text-secondary)] tracking-widest uppercase">Threat Intelligence</p>
        </div>
      </div>
      <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
        {SECTIONS.map((section) => (
          <CollapsibleSection
            key={section.label}
            section={section}
            pathname={pathname}
            badges={badges}
          />
        ))}
        <div className="my-2 border-t border-[var(--border)] opacity-30" />
        {BOTTOM_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`sidebar-link ${pathname.startsWith(item.href) ? "active" : ""}`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-[var(--border)] p-3">
        <div className="flex items-center gap-2 mb-2">
          <div className="w-8 h-8 rounded-full bg-[var(--bg-tertiary)] flex items-center justify-center shrink-0">
            <User className="w-4 h-4 text-[var(--text-secondary)]" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium truncate">{user.name || user.email}</p>
            <p className={`text-[10px] font-semibold uppercase ${ROLE_COLORS[user.role] ?? "text-[var(--text-secondary)]"}`}>
              {user.role}
            </p>
          </div>
          <form action={logout}>
            <button
              type="submit"
              className="p-1.5 rounded hover:bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-red-400 transition-colors"
              title="Sign out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </form>
        </div>
      </div>
    </aside>
  );
}
