import { useCallback, useEffect, useState, useSyncExternalStore } from "react";

// ---------------------------------------------------------------- hash router
// Five routes do not justify a router dependency (see ADR-0002).

function readHash(): string {
  const raw = window.location.hash.replace(/^#/, "");
  return raw.startsWith("/") ? raw : "/";
}

function subscribe(cb: () => void): () => void {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
}

export function useRoute(): { path: string; query: URLSearchParams } {
  const hash = useSyncExternalStore(subscribe, readHash);
  const [path = "/", qs = ""] = hash.split("?");
  return { path, query: new URLSearchParams(qs) };
}

export function navigate(to: string, replace = false): void {
  const target = `#${to}`;
  if (replace) window.history.replaceState(null, "", target);
  else window.location.hash = to;
  if (replace) window.dispatchEvent(new HashChangeEvent("hashchange"));
}

// ------------------------------------------------------------------ data

export interface Async<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
  setData: (d: T) => void;
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    fn()
      .then((d) => alive && setData(d))
      .catch((e: unknown) => alive && setError(e instanceof Error ? e : new Error(String(e))))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, error, loading, reload, setData };
}

// ----------------------------------------------------------------- theme

export type Theme = "light" | "dark" | "system";

function storedTheme(): Theme {
  try {
    const v = window.localStorage.getItem("argus.theme");
    if (v === "light" || v === "dark") return v;
  } catch {
    /* storage unavailable: fall back to system */
  }
  return "system";
}

export function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      if (theme === "system") window.localStorage.removeItem("argus.theme");
      else window.localStorage.setItem("argus.theme", theme);
    } catch {
      /* non-persistent is fine */
    }
  }, [theme]);
  return [theme, setTheme];
}
