import type { ReactNode } from "react";
import { useRoute, useTheme, type Theme } from "./hooks";
import { Overview } from "./pages/Overview";
import { Scenarios } from "./pages/Scenarios";
import { ScenarioView } from "./pages/ScenarioView";
import { Playground } from "./pages/Playground";
import { Experiments } from "./pages/Experiments";

const icon = (d: string) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d={d} />
  </svg>
);

const NAV: { to: string; label: string; icon: ReactNode }[] = [
  { to: "/", label: "Overview", icon: icon("M3 12l9-8 9 8M5 10v10h14V10") },
  { to: "/scenarios", label: "Scenarios", icon: icon("M4 6h16M4 12h16M4 18h10") },
  { to: "/playground", label: "Gateway playground", icon: icon("M5 4l14 8-14 8V4z") },
  { to: "/experiments", label: "Experiments", icon: icon("M4 20V10M10 20V4M16 20v-7M22 20H2") },
];

function ThemeToggle() {
  const [theme, setTheme] = useTheme();
  const opts: Theme[] = ["system", "light", "dark"];
  return (
    <div className="seg" role="group" aria-label="Colour theme">
      {opts.map((t) => (
        <button key={t} aria-pressed={theme === t} onClick={() => setTheme(t)}>
          {t[0]!.toUpperCase() + t.slice(1)}
        </button>
      ))}
    </div>
  );
}

export function App() {
  const { path, query } = useRoute();
  const parts = path.split("/").filter(Boolean);
  const section = `/${parts[0] ?? ""}`;

  let page: ReactNode;
  if (section === "/") page = <Overview />;
  else if (section === "/scenarios" && parts[1]) page = <ScenarioView id={decodeURIComponent(parts[1])} />;
  else if (section === "/scenarios") page = <Scenarios />;
  else if (section === "/playground") page = <Playground sessionId={query.get("s")} scenarioId={query.get("scenario")} />;
  else if (section === "/experiments") page = <Experiments />;
  else
    page = (
      <div className="empty">
        Page not found. <a href="#/">Back to overview</a>
      </div>
    );

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#/" aria-label="ARGUS home">
          <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden>
            <rect width="32" height="32" rx="7" fill="#184f95" />
            <path d="M4 16c3.5-6 7.5-9 12-9s8.5 3 12 9c-3.5 6-7.5 9-12 9s-8.5-3-12-9z" fill="none" stroke="#fff" strokeWidth="2.2" />
            <circle cx="16" cy="16" r="4" fill="#fff" />
          </svg>
          <span>
            <div className="brand-name" style={{ color: "var(--ink)" }}>ARGUS</div>
            <div className="brand-sub">Agent runtime monitor · PoC</div>
          </span>
        </a>
        <nav className="nav" aria-label="Main">
          {NAV.map((n) => (
            <a key={n.to} href={`#${n.to}`} aria-current={section === n.to ? "page" : undefined}>
              {n.icon}
              <span>{n.label}</span>
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <ThemeToggle />
          <span className="foot-text">
            Research prototype. Synthetic, author-written scenarios. Fake tools only.
          </span>
        </div>
      </aside>
      <main className="main">{page}</main>
    </div>
  );
}
