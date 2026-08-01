import { describe, expect, it } from "vitest";
import { COMMAND_DESCRIPTORS } from "@forgewire/fabric-client-core";
import { DESKTOP_COMMANDS, searchDesktopCommands } from "./commandCatalog";

describe("desktop command discovery", () => {
  it("documents every reference command without missing or unknown classifications", () => {
    expect(DESKTOP_COMMANDS).toHaveLength(58);
    expect(new Set(DESKTOP_COMMANDS.map((item) => item.id)).size).toBe(58);
    expect(DESKTOP_COMMANDS.map((item) => item.id)).toEqual(COMMAND_DESCRIPTORS.map((item) => item.id));
    expect(DESKTOP_COMMANDS.every((item) => item.availability === "supported" || item.availability === "contextual" || Boolean(item.alternative))).toBe(true);
    expect(DESKTOP_COMMANDS.filter((item) => item.availability === "platform-alternative").every((item) => Boolean(item.alternative))).toBe(true);
  });

  it("finds commands by label, id, category, and desktop alternative", () => {
    expect(searchDesktopCommands("cancel task").map((item) => item.id)).toContain("forgewire.cancelTask");
    expect(searchDesktopCommands("SYSTEM SSH").map((item) => item.id)).toContain("forgewire.dr.provisionSshForSystem");
    expect(searchDesktopCommands("protected WebView").map((item) => item.id)).toContain("forgewire.copyToken");
  });
});
