import { useCallback, useEffect, useState } from "react";

const ROUTE_KEY = "forgewire.fabric.desktop.route.v1";
const DEFAULT_ROUTE = "/dashboard";

export type ActivityId =
  | "dashboard"
  | "explorer"
  | "fleet"
  | "tasks"
  | "agents"
  | "approvals"
  | "cost"
  | "audit"
  | "secrets"
  | "settings"
  | "account";

export const ACTIVITY_ROUTES: Record<ActivityId, string> = {
  dashboard: "/dashboard",
  explorer: "/explorer",
  fleet: "/hub/active",
  tasks: "/tasks/all",
  agents: "/agents/all",
  approvals: "/approvals/all",
  cost: "/cost",
  audit: "/audit",
  secrets: "/secrets",
  settings: "/settings/connection",
  account: "/account"
};

function safeRoute(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.includes("?") || value.includes("#")) {
    return DEFAULT_ROUTE;
  }
  return value;
}

function currentRoute(): string {
  const fromHash = window.location.hash.replace(/^#/, "");
  if (fromHash) {
    return safeRoute(fromHash);
  }
  try {
    return safeRoute(window.localStorage.getItem(ROUTE_KEY));
  } catch {
    return DEFAULT_ROUTE;
  }
}

export function activityForRoute(route: string): ActivityId {
  if (route === DEFAULT_ROUTE) return "dashboard";
  if (route === "/explorer") return "explorer";
  if (/^\/(hub|cluster|hosts|runners|dispatchers)\//.test(route)) return "fleet";
  if (route.startsWith("/tasks/")) return "tasks";
  if (route.startsWith("/agents/")) return "agents";
  if (route.startsWith("/approvals/")) return "approvals";
  if (route === "/cost") return "cost";
  if (route.startsWith("/audit")) return "audit";
  if (route === "/secrets") return "secrets";
  if (route.startsWith("/settings")) return "settings";
  if (route.startsWith("/account")) return "account";
  return "dashboard";
}

export function useHashRoute() {
  const [route, setRoute] = useState(currentRoute);

  useEffect(() => {
    if (!window.location.hash) {
      window.history.replaceState(null, "", `#${route}`);
    }
    const onChange = () => setRoute(currentRoute());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(ROUTE_KEY, safeRoute(route));
    } catch {
      // Navigation remains functional when persistence is unavailable.
    }
  }, [route]);

  const navigate = useCallback((next: string, replace = false) => {
    const safe = safeRoute(next);
    if (replace) {
      window.history.replaceState(null, "", `#${safe}`);
      setRoute(safe);
    } else if (window.location.hash !== `#${safe}`) {
      window.location.hash = safe;
    }
  }, []);

  return { route, activity: activityForRoute(route), navigate };
}
