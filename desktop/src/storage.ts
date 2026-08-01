import { invoke } from "@tauri-apps/api/core";
import type { FabricContext, GuiConfig, HubConfig } from "./types";

const CONFIG_KEY = "forgewire.fabric.desktop.hub";

export function loadInitialHubConfig(): HubConfig {
  const fallback: HubConfig = { hubUrl: "http://127.0.0.1:8765", tokenPresent: false };
  try {
    const raw = window.localStorage.getItem(CONFIG_KEY);
    const parsed = raw ? (JSON.parse(raw) as { hubUrl?: unknown }) : {};
    return {
      hubUrl: typeof parsed.hubUrl === "string" ? parsed.hubUrl : fallback.hubUrl,
      tokenPresent: false
    };
  } catch {
    return fallback;
  }
}

export function hubConfigFromContext(context: FabricContext, fallback: HubConfig): HubConfig {
  return {
    hubUrl: typeof context.hub_url === "string" && context.hub_url ? context.hub_url : fallback.hubUrl,
    tokenPresent: context.token_present === true
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
  if (context) return hubConfigFromContext(context, fallback);
  try {
    const guiConfig = await invoke<GuiConfig>("load_gui_config");
    return {
      hubUrl: typeof guiConfig.hub_url === "string" && guiConfig.hub_url ? guiConfig.hub_url : fallback.hubUrl,
      tokenPresent: fallback.tokenPresent
    };
  } catch {
    return fallback;
  }
}

export async function saveHubConfig(config: HubConfig): Promise<void> {
  const hubUrl = config.hubUrl.trim().replace(/\/+$/, "");
  window.localStorage.setItem(CONFIG_KEY, JSON.stringify({ hubUrl }));
  let current: GuiConfig = { hub_url: hubUrl, hub_candidates: [], hub_pin: null, refresh_interval_seconds: 10 };
  try {
    current = await invoke<GuiConfig>("load_gui_config");
  } catch {
    // Browser-only preview retains only the non-sensitive URL fallback.
  }
  try {
    await invoke<GuiConfig>("save_gui_config", {
      config: { ...current, hub_url: hubUrl }
    });
  } catch {
    // Browser-only preview retains only the non-sensitive URL fallback.
  }
}
