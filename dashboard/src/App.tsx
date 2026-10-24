import { useEffect, useState, type ReactNode } from "react";
import { useRoute, useTheme, type Theme } from "./hooks";
import { Callout } from "./components/ui";
import { Overview } from "./pages/Overview";
import { Benchmark } from "./pages/Benchmark";
import { Trajectory } from "./pages/Trajectory";
import { Live } from "./pages/Live";
import { Approvals } from "./pages/Approvals";
import { Forensics } from "./pages/Forensics";
import { Results } from "./pages/Results";
import { Demo } from "./pages/Demo";
import { Scenarios } from "./pages/Scenarios";
import { ScenarioView } from "./pages/ScenarioView";
import { Experiments } from "./pages/Experiments";

const icon = (d: string) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d={d} />
  </svg>
);

const NAV: { to: string; label: string; icon: ReactNode }[] = [
  { to: "/", label: "Overview", icon: icon("M3 12l9-8 9 8M5 10v10h14V10") },
  { to: "/demo", label: "Demo", icon: icon("M5 4l14 8-14 8V4z") },
  { to: "/bench", label: "Benchmark", icon: icon("M4 6h16M4 12h16M4 18h10") },
  { to: "/live", label: "Live session", icon: icon("M12 3v18M3 12h18") },
  { to: "/approvals", label: "Approvals", icon: icon("M5 12l4 4 10-10") },
  { to: "/forensics", label: "Forensics", icon: icon("M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-4.5-4.5") },
  { to: "/results", label: "Results", icon: icon("M4 20V10M10 20V4M16 20v-7M22 20H2") },
  { to: "/archive", label: "Archive (PoC)", icon: icon("M4 7h16v13H4zM2 3h20v4H2zM10 12h4") },
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

function PresenterToggle() {
  const [on, setOn] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem("argus.presenter") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("presenter", on);
    try {
      window.localStorage.setItem("argus.presenter", on ? "1" : "0");
    } catch {
      /* non-persistent is fine */
    }
  }, [on]);
  return (
    <button className="btn sm" aria-pressed={on} onClick={() => setOn(!on)} title="Larger text for a projector">
      {on ? "Presenter: on" : "Presenter: off"}
    </button>
  );
}

export function App() {
  const { path, query } = useRoute();
  const parts = path.split("/").filter(Boolean);
  const section = `/${parts[0] ?? ""}`;

  let page: ReactNode;
  if (section === "/") page = <Overview />;
  else if (section === "/demo") page = <Demo index={Number(query.get("b") ?? 0) || 0} />;
  else if (section === "/bench" && parts[1]) page = <Trajectory id={decodeURIComponent(parts[1])} />;
  else if (section === "/bench") page = <Benchmark />;
  else if (section === "/live") page = <Live sessionId={query.get("s")} />;
  else if (section === "/approvals") page = <Approvals />;
  else if (section === "/forensics") page = <Forensics id={parts[1] ? decodeURIComponent(parts[1]) : null} />;
  else if (section === "/results") page = <Results />;
  else if (section === "/archive" && parts[1] === "scenarios" && parts[2])
    page = <ScenarioView id={decodeURIComponent(parts[2])} />;
  else if (section === "/archive" && parts[1] === "experiment") page = <Experiments />;
  else if (section === "/archive")
    page = (
      <div className="stack">
        <Callout tone="neutral" icon="i" title="Archive: the v0 proof of concept (read-only)">
          Ten hand-written scenarios, an IsolationForest on 12 features and a mock intent judge. It failed G3 (ML AUROC 0.536),
          which motivated AgentEscapeBench, features v2 and everything since. <a href="#/archive/experiment">PoC experiment →</a>
        </Callout>
        <Scenarios />
      </div>
    );
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
            <div className="brand-sub">Runtime behavioural security</div>
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
          <PresenterToggle />
          <ThemeToggle />
          <span className="foot-text">
            Research prototype. Synthetic, author-written scenarios. Fake tools only. Local, no auth.
          </span>
        </div>
      </aside>
      <main className="main">{page}</main>
    </div>
  );
}
