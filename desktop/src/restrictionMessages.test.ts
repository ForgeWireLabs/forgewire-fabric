import { describe, expect, it } from "vitest";
import { accountRoleContextNote } from "./restrictionMessages";

describe("accountRoleContextNote", () => {
  it("adds nothing when no human session is signed in", () => {
    expect(accountRoleContextNote(null)).toBe("");
  });

  it("names the signed-in account's own roles, distinct from the automation token", () => {
    const note = accountRoleContextNote(["admin"]);
    expect(note).toContain("admin");
    expect(note).toContain("separate credential from the installed automation token");
  });

  it("reports 'none' rather than an empty list for a signed-in account with no roles", () => {
    expect(accountRoleContextNote([])).toContain("(none)");
  });

  it("joins multiple account roles", () => {
    expect(accountRoleContextNote(["admin", "reviewer"])).toContain("admin, reviewer");
  });
});
