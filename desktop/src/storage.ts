import type { FabricContext, HubConfig } from "./types";
import { invoke } from "@tauri-apps/api/core";
import type { GuiConfig } from "./types";

const CONFIG_KEY = "forgewire.fabric.desktop.hub";
const TOKEN_KEY = "forgewire.fabric.desktop.token";

export function loadInitialHubConfig(): HubConfig {
  const fallback: HubConfig = { hubUrl: "http://127.0.0.1:8765", token: "" };
  try {
    const raw = window.localStorage.getItem(CONFIG_KEY);
    const parsed = raw ? (JSON.parse(raw) as Partial<HubConfig>) : {};
    return {
      hubUrl: typeof parsed.hubUrl === "string" ? parsed.hubUrl : fallback.hubUrl,
      token: window.localStorage.getItem(TOKEN_KEY) ?? fallback.token
    };
  } catch {
    return fallback;
  }
}

export function hubConfigFromContext(context: FabricContext, fallback: HubConfig): HubConfig {
  return {
    hubUrl: typeof context.hub_url === "string" && context.hub_url ? context.hub_url : fallback.hubUrl,
    token: typeof context.token === "string" ? context.token : fallback.token
  };
}

export async function loadFabricContext(): Promise<FabricContext | null> {
  try {
    return await invoke<FabricContext>("load_fabric_context");
  } catch {
    return null;
  }
}

export async function loadHubConfig(): Promise<HubConfig> {
  const fallback = loadInitialHubConfig();
  const context = await loadFabricContext();
  if (context) {
    return hubConfigFromContext(context, fallback);
  }
  try {
    const guiConfig = await invoke<GuiConfig>("load_gui_config");
    return {
      hubUrl: typeof guiConfig.hub_url === "string" && guiConfig.hub_url ? guiConfig.hub_url : fallback.hubUrl,
      token: fallback.token
    };
  } catch {
    return fallback;
  }
}

export async function saveHubConfig(config: HubConfig): Promise<void> {
  const hubUrl = config.hubUrl.trim().replace(/\/+$/, "");
  window.localStorage.setItem(CONFIG_KEY, JSON.stringify({ hubUrl }));
  window.localStorage.removeItem(TOKEN_KEY);

  try {
    await invoke<GuiConfig>("save_gui_config", {
      config: {
        hub_url: hubUrl,
        hub_candidates: []
      }
    });
  } catch {
    // Browser-only dev mode falls back to localStorage.
  }
}
