import { readFileSync } from "node:fs";
import {
  COMMAND_DESCRIPTORS,
  COMMAND_IDS,
  VIEW_IDS,
  commandAvailability,
} from "@forgewire/fabric-client-core";

const bundle = readFileSync(new URL("../dist/extension.js", import.meta.url), "utf8");
const extensionSource = readFileSync(new URL("../src/extension.ts", import.meta.url), "utf8");
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const unresolvedCoreImport = /require\(["']@forgewire\/fabric-client-core["']\)/;

const commandIds = manifest.contributes.commands.map(({ command }) => command);
const viewIds = manifest.contributes.views.forgewire.map(({ id }) => id);
const paletteIds = manifest.contributes.menus.commandPalette.map(({ command }) => command);
const costTitleActions = manifest.contributes.menus["view/title"].filter(
  ({ when }) => when === "view == forgewire.cost"
);

assertExactIds("commands", commandIds, COMMAND_IDS);
assertExactIds("views", viewIds, VIEW_IDS);
assertCommandContract();
assertExtensionRegistrations();
assertMenuCommands();
if (new Set(paletteIds).size !== paletteIds.length) {
  throw new Error("commandPalette contains duplicate command rows");
}
if (!costTitleActions.some(({ command }) => command === "forgewire.cost.refresh")) {
  throw new Error("Cost view is missing its title-bar refresh action");
}

if (unresolvedCoreImport.test(bundle)) {
  throw new Error("dist/extension.js contains an unresolved fabric-client-core require");
}
if (!bundle.includes("activate")) {
  throw new Error("dist/extension.js does not export the VSIX activation entry point");
}

console.log(`verified ${COMMAND_IDS.length} commands, ${VIEW_IDS.length} views, manifest actions, and bundled fabric-client-core`);

function assertExactIds(label, actual, expected) {
  if (actual.length !== expected.length || actual.some((id, index) => id !== expected[index])) {
    throw new Error(`${label} do not match the shared canonical order`);
  }
}

function assertCommandContract() {
  assertExactIds(
    "command descriptors",
    COMMAND_DESCRIPTORS.map(({ id }) => id),
    COMMAND_IDS
  );

  const vscodeSpecific = COMMAND_DESCRIPTORS.filter(
    ({ parityClass }) => parityClass === "vscode_specific"
  );
  const classificationCounts = COMMAND_DESCRIPTORS.reduce((counts, { parityClass }) => {
    counts[parityClass] = (counts[parityClass] ?? 0) + 1;
    return counts;
  }, {});
  const actualCounts = ["core", "equivalent", "vscode_specific"].map(
    (parityClass) => classificationCounts[parityClass] ?? 0
  );
  const expectedCounts = [20, 32, 6];
  if (actualCounts.some((count, index) => count !== expectedCounts[index])) {
    throw new Error(
      `command classification drifted (core/equivalent/vscode-specific): ` +
        `${actualCounts.join("/")} != ${expectedCounts.join("/")}`
    );
  }
  const undocumentedAlternatives = vscodeSpecific.filter(
    ({ desktopAlternative }) => !desktopAlternative?.trim()
  );
  if (undocumentedAlternatives.length > 0) {
    throw new Error(
      `VS Code-specific commands lack desktop alternatives: ` +
        undocumentedAlternatives.map(({ id }) => id).join(", ")
    );
  }

  for (const descriptor of COMMAND_DESCRIPTORS) {
    const selectionStatus = descriptor.selectionStatuses?.[0];
    const availability = commandAvailability(descriptor, {
      sessionState: "connected",
      selection: descriptor.selectionKind === undefined
        ? undefined
        : { kind: descriptor.selectionKind, id: "contract-audit", status: selectionStatus },
      features: new Set(descriptor.feature === undefined ? [] : [descriptor.feature]),
      authorities: new Set(descriptor.authority === undefined ? [] : [descriptor.authority]),
      humanRoles: new Set(descriptor.requiresHumanRole === undefined ? [] : [descriptor.requiresHumanRole]),
      freshness: "live",
      platform: "vscode",
      identity: "dispatcher",
    });
    if (!availability.enabled) {
      throw new Error(
        `Canonical VSIX availability rejects ${descriptor.id}: ${availability.reason}`
      );
    }
  }

  const specificSection = readme.match(
    /### VS Code-specific commands([\s\S]*?)(?:\n## |$)/u
  )?.[1] ?? "";
  const documentedSpecificRows = [...specificSection.matchAll(
    /^\| `(forgewire\.[^`]+)` \| (.+) \|$/gmu
  )].map(([, id, desktopAlternative]) => ({ id, desktopAlternative }));
  assertExactSet(
    "documented VS Code-specific commands",
    documentedSpecificRows.map(({ id }) => id),
    vscodeSpecific.map(({ id }) => id)
  );
  for (const descriptor of vscodeSpecific) {
    const documented = documentedSpecificRows.find(({ id }) => id === descriptor.id);
    if (documented?.desktopAlternative !== descriptor.desktopAlternative) {
      throw new Error(
        `documented desktop alternative drifted for ${descriptor.id}: ` +
          `${JSON.stringify(documented?.desktopAlternative)} != ` +
          `${JSON.stringify(descriptor.desktopAlternative)}`
      );
    }
  }
}

function assertExtensionRegistrations() {
  const handlerBlock = extensionSource.match(
    /const commandHandlers: Record<CommandId,[\s\S]*?= \{([\s\S]*?)\n  \};/
  )?.[1];
  if (handlerBlock === undefined) {
    throw new Error("could not locate the typed commandHandlers registration table");
  }
  const handlerIds = [...handlerBlock.matchAll(/^    "([^"]+)":/gmu)].map(
    ([, id]) => id
  );
  assertExactSet("extension command handlers", handlerIds, COMMAND_IDS);

  const providerBlock = extensionSource.match(
    /const viewProviders: Record<ViewId,[\s\S]*?= \{([\s\S]*?)\n  \};/
  )?.[1];
  if (providerBlock === undefined) {
    throw new Error("could not locate the typed viewProviders registration table");
  }
  const providerIds = [...providerBlock.matchAll(/^    "([^"]+)":/gmu)].map(
    ([, id]) => id
  );
  assertExactIds("extension view providers", providerIds, VIEW_IDS);

  if (!extensionSource.includes("...COMMAND_DESCRIPTORS.map(({ id }) =>")) {
    throw new Error("extension activation does not register the shared command descriptor set");
  }
  if (!extensionSource.includes("...VIEW_IDS.map((viewId) =>")) {
    throw new Error("extension activation does not register the shared canonical view set");
  }
  if (!/\.secrets\.store\(SECRET_TOKEN_KEY/u.test(extensionSource) ||
      !/\.secrets\.get\(SECRET_TOKEN_KEY/u.test(extensionSource)) {
    throw new Error("hub token flow no longer uses VS Code SecretStorage");
  }
}

function assertExactSet(label, actual, expected) {
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  const missing = expected.filter((id) => !actualSet.has(id));
  const extra = actual.filter((id) => !expectedSet.has(id));
  if (actual.length !== expected.length || actualSet.size !== actual.length || missing.length || extra.length) {
    throw new Error(
      `${label} are not a one-to-one match; missing=[${missing.join(", ")}], ` +
        `extra=[${extra.join(", ")}]`
    );
  }
}

function assertMenuCommands() {
  const declared = new Set(COMMAND_IDS);
  const unknown = Object.entries(manifest.contributes.menus).flatMap(
    ([menu, rows]) => rows
      .filter(({ command }) => !declared.has(command))
      .map(({ command }) => `${menu}:${command}`)
  );
  if (unknown.length > 0) {
    throw new Error(`manifest menus reference undeclared commands: ${unknown.join(", ")}`);
  }
}
